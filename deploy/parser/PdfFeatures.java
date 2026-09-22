/* Bounded, content-free PDF feature inventory. Compiled against the packaged Tika jar.
 * This is an eligibility check, not a replacement for native extraction/page OCR.
 * Caller must enforce a three-second wall deadline, memory limit, and private input.
 */
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.io.RandomAccessReadBufferedFile;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

public final class PdfFeatures {
    private static final int MAX_NODES = 20000, MAX_DEPTH = 64, MAX_PAGES = 100;
    private static final int MAX_CONTENT = 4 * 1024 * 1024, MAX_TOKENS = 200000;
    private static final Set<String> ANNOTATION_TYPES = Set.of("Text", "Link", "FreeText", "Line", "Square", "Circle",
            "Polygon", "PolyLine", "Highlight", "Underline", "Squiggly", "StrikeOut", "Stamp", "Caret", "Ink",
            "Popup", "FileAttachment", "Sound", "Movie", "Widget", "Screen", "PrinterMark", "TrapNet",
            "Watermark", "3D", "Redact", "RichMedia");
    private static final Set<String> PIXEL_ONLY_FILTERS = Set.of("FlateDecode", "LZWDecode", "RunLengthDecode",
            "ASCIIHexDecode", "ASCII85Decode", "CCITTFaxDecode");
    private final long deadline = System.nanoTime() + 2500000000L;
    private int nodes, tokens, contentBytes;
    private Integer pages;
    private Boolean encrypted;
    private boolean canExtract, complete;
    private String status = "failed";
    private final Map<String, Integer> counts = new LinkedHashMap<>();
    private final Set<String> reasons = new LinkedHashSet<>();
    private final Set<COSBase> visited = identitySet();
    private final Set<COSStream> pageStreams = identitySet(), harmlessStreams = identitySet();
    private final Set<COSStream> images = identitySet(), usedImages = identitySet();
    private static volatile boolean parserWarning;

    private static <T> Set<T> identitySet() { return Collections.newSetFromMap(new IdentityHashMap<T, Boolean>()); }
    private static COSName key(String s) { return COSName.getPDFName(s); }
    private static COSBase value(COSDictionary d, String s) { return d.getDictionaryObject(key(s)); }
    private static boolean present(COSDictionary d, String s) { COSBase v = value(d, s); return v != null && v != COSNull.NULL; }
    private static String name(COSDictionary d, String s) { COSBase v = value(d, s); return v instanceof COSName ? ((COSName)v).getName() : ""; }
    private static boolean pixelOnlyFilters(COSBase filter) {
        if (filter == null || filter == COSNull.NULL) return true;
        if (filter instanceof COSName) return PIXEL_ONLY_FILTERS.contains(((COSName)filter).getName());
        if (!(filter instanceof COSArray)) return false;
        COSArray filters = (COSArray)filter;
        if (filters.size() < 1 || filters.size() > 16) return false;
        for (int i = 0; i < filters.size(); i++) {
            COSBase item = filters.getObject(i);
            if (!(item instanceof COSName) || !PIXEL_ONLY_FILTERS.contains(((COSName)item).getName())) return false;
        }
        return true;
    }
    private void inc(String field) { counts.put(field, counts.get(field) + 1); }
    private void check(int depth) throws Limit {
        if (++nodes > MAX_NODES || depth > MAX_DEPTH || System.nanoTime() > deadline) throw new Limit();
    }
    private static final class Limit extends IOException { }

    private PdfFeatures() {
        for (String field : new String[]{"annotations", "unknown_annotations", "forms", "xfa", "layers",
                "embedded_name_trees", "associated_files", "file_specifications", "embedded_streams",
                "actions", "metadata", "other_text", "interactive_features", "unknown_streams",
                "image_resources", "image_uses", "unused_images", "unverified_image_uses",
                "unsupported_resources", "unsupported_operators", "unknown_structure", "parser_warnings",
                "nondefault_user_units", "native_text_operations"}) counts.put(field, 0);
    }

    private static void quietLogging() {
        // Keep a warning bit, never parser diagnostics (which can contain patient text).
        LoggerContext context = LoggerContext.getContext(false);
        Configuration config = context.getConfiguration();
        AbstractAppender counter = new AbstractAppender("coverage-counter", null, null, true) {
            @Override public void append(LogEvent event) {
                if (event.getLevel().isMoreSpecificThan(Level.WARN)) parserWarning = true;
            }
        };
        counter.start();
        config.addAppender(counter);
        List<LoggerConfig> loggers = new ArrayList<>(config.getLoggers().values());
        loggers.add(config.getRootLogger());
        for (LoggerConfig logger : loggers) {
            for (String appender : new ArrayList<>(logger.getAppenders().keySet())) logger.removeAppender(appender);
            logger.setLevel(Level.WARN);
            logger.addAppender(counter, Level.WARN, null);
        }
        context.updateLoggers();
    }

    private void collectStreams(COSBase base) throws IOException {
        check(0);
        if (base == null || base == COSNull.NULL) return;
        if (base instanceof COSStream) { pageStreams.add((COSStream)base); return; }
        if (base instanceof COSArray) {
            COSArray a = (COSArray)base;
            if (a.size() > MAX_NODES) throw new Limit();
            for (int i = 0; i < a.size(); i++) {
                COSBase item = a.getObject(i);
                if (!(item instanceof COSStream)) { inc("unknown_structure"); continue; }
                pageStreams.add((COSStream)item);
            }
            return;
        }
        inc("unknown_structure");
    }

    private void walk(COSBase base, int depth, boolean skipStrings) throws IOException {
        check(depth);
        if (base instanceof COSObject) { walk(((COSObject)base).getObject(), depth + 1, skipStrings); return; }
        if (base == null || base == COSNull.NULL) return;
        if (base instanceof COSString) { if (!skipStrings) inc("other_text"); return; }
        if (!visited.add(base)) return;
        if (base instanceof COSArray) {
            COSArray array = (COSArray)base;
            if (array.size() > MAX_NODES) throw new Limit();
            for (int i = 0; i < array.size(); i++) walk(array.get(i), depth + 1, skipStrings);
            return;
        }
        if (!(base instanceof COSDictionary)) return;
        COSDictionary d = (COSDictionary)base;
        String type = name(d, "Type"), subtype = name(d, "Subtype");
        // Do not use PDPage.getUserUnit(): it silently substitutes the default
        // for malformed/nonpositive values. Check every dictionary, including
        // a misplaced/inherited declaration, before trusting page coordinates.
        if (d.containsKey(key("UserUnit"))) {
            COSBase unit = value(d, "UserUnit");
            if (!(unit instanceof COSNumber) || ((COSNumber)unit).floatValue() != 1.0f
                    || !"Page".equals(type)) inc("nondefault_user_units");
        }
        if (present(d, "AcroForm") || "AcroForm".equals(type)) inc("forms");
        if (present(d, "XFA")) inc("xfa");
        if (present(d, "OCProperties") || present(d, "OC") || "OCG".equals(type) || "OCMD".equals(type)) inc("layers");
        if (present(d, "EmbeddedFiles")) inc("embedded_name_trees");
        if (present(d, "AF")) inc("associated_files");
        if ("Filespec".equals(type) || present(d, "EF")) inc("file_specifications");
        if ("EmbeddedFile".equals(type)) inc("embedded_streams");
        if (present(d, "OpenAction") || present(d, "AA") || present(d, "A") || present(d, "JS")
                || present(d, "JavaScript") || "Action".equals(type)) inc("actions");
        if (present(d, "Metadata") || "Metadata".equals(type)) inc("metadata");
        if (present(d, "Collection") || present(d, "RichMediaContent") || present(d, "Movie")
                || present(d, "Sound") || present(d, "3DD") || present(d, "Outlines")
                || present(d, "StructTreeRoot") || present(d, "PieceInfo")) inc("interactive_features");
        if ("Form".equals(subtype) || "Type3".equals(subtype) || present(d, "Pattern")
                || present(d, "Shading") || present(d, "ExtGState") || present(d, "Properties")) inc("unsupported_resources");
        if (base instanceof COSStream) {
            COSStream stream = (COSStream)base;
            if ("Image".equals(subtype)) {
                images.add(stream);
                inc("image_resources");
                // Rasterizing a JPEG/JPX/JBIG2 stream does not inspect its
                // internal comment/EXIF/XMP/extension metadata. Such encoded
                // images need a separate inventory before whole-object coverage
                // can be asserted. Raw/lossless pixel filters remain eligible.
                if (!pixelOnlyFilters(value(d, "Filter"))) inc("unverified_image_uses");
                if (present(d, "SMask") || present(d, "Mask") || d.getBoolean(key("ImageMask"), false)
                        || present(d, "Alternates") || present(d, "OPI")) inc("unverified_image_uses");
            } else if (!pageStreams.contains(stream) && !harmlessStreams.contains(stream)
                    && !"XRef".equals(type) && !"ObjStm".equals(type)) inc("unknown_streams");
        }
        if (d.size() > MAX_NODES) throw new Limit();
        for (Map.Entry<COSName, COSBase> entry : d.entrySet()) {
            String field = entry.getKey().getName();
            COSBase child = d.getDictionaryObject(entry.getKey());
            // Font programs and encoding maps are not document text. Never decode them here.
            if (Set.of("FontFile", "FontFile2", "FontFile3", "ToUnicode").contains(field) && child instanceof COSStream)
                harmlessStreams.add((COSStream)child);
            // Trailer IDs are binary identifiers, not document metadata or source filenames.
            walk(entry.getValue(), depth + 1, "ID".equals(field) && d.containsKey(key("Root")));
        }
    }

    private byte[] content(PDPage page) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = page.getContents()) {
            byte[] chunk = new byte[8192];
            int n;
            while ((n = input.read(chunk)) != -1) {
                check(0);
                contentBytes += n;
                if (contentBytes > MAX_CONTENT) throw new Limit();
                output.write(chunk, 0, n);
            }
        }
        return output.toByteArray();
    }

    private static boolean contains(PDRectangle box, double x, double y) {
        return Double.isFinite(x) && Double.isFinite(y) && x >= box.getLowerLeftX() - .01
                && x <= box.getUpperRightX() + .01 && y >= box.getLowerLeftY() - .01 && y <= box.getUpperRightY() + .01;
    }

    private void pageContent(PDPage page) throws IOException {
        PDFStreamParser parser = new PDFStreamParser(content(page));
        List<COSBase> operands = new ArrayList<>();
        ArrayDeque<AffineTransform> stack = new ArrayDeque<>();
        AffineTransform matrix = new AffineTransform();
        List<Rectangle2D> imageBoxes = new ArrayList<>();
        boolean clip = false, imagesOnPage = false;
        try {
            Object token;
            while ((token = parser.parseNextToken()) != null) {
                check(0);
                if (++tokens > MAX_TOKENS) throw new Limit();
                if (!(token instanceof Operator)) {
                    if (!(token instanceof COSBase) || operands.size() >= 64) throw new Limit();
                    operands.add((COSBase)token);
                    continue;
                }
                String op = ((Operator)token).getName();
                // Informational source inventory, not a claim that glyphs were
                // decoded. Even an empty or malformed show operation prevents
                // the narrow proof that a page has no native text to account for.
                if (Set.of("Tj", "TJ", "'", "\"").contains(op)) inc("native_text_operations");
                switch (op) {
                    case "q":
                        if (!operands.isEmpty() || stack.size() >= MAX_DEPTH) throw new Limit();
                        stack.push(new AffineTransform(matrix)); break;
                    case "Q":
                        if (!operands.isEmpty() || stack.isEmpty()) { inc("unknown_structure"); break; }
                        matrix = stack.pop(); break;
                    case "cm":
                        if (operands.size() != 6 || operands.stream().anyMatch(v -> !(v instanceof COSNumber))) { inc("unknown_structure"); break; }
                        double[] v = new double[6];
                        for (int i = 0; i < 6; i++) v[i] = ((COSNumber)operands.get(i)).floatValue();
                        matrix.concatenate(new AffineTransform(v)); break;
                    case "Do":
                        if (operands.size() != 1 || !(operands.get(0) instanceof COSName) || page.getResources() == null) { inc("unknown_structure"); break; }
                        COSBase resources = value(page.getResources().getCOSObject(), "XObject");
                        COSBase object = resources instanceof COSDictionary ? ((COSDictionary)resources).getDictionaryObject((COSName)operands.get(0)) : null;
                        if (!(object instanceof COSStream) || !"Image".equals(name((COSDictionary)object, "Subtype"))) { inc("unsupported_resources"); break; }
                        COSStream image = (COSStream)object;
                        usedImages.add(image); inc("image_uses"); imagesOnPage = true;
                        boolean verified = !clip && Math.abs(matrix.getDeterminant()) > .001;
                        Rectangle2D bounds = null;
                        for (int x = 0; x <= 1; x++) for (int y = 0; y <= 1; y++) {
                            Point2D p = matrix.transform(new Point2D.Double(x, y), null);
                            verified &= contains(page.getMediaBox(), p.getX(), p.getY()) && contains(page.getCropBox(), p.getX(), p.getY());
                            if (bounds == null) bounds = new Rectangle2D.Double(p.getX(), p.getY(), 0, 0); else bounds.add(p);
                        }
                        for (Rectangle2D other : imageBoxes) if (other.intersects(bounds)) verified = false;
                        imageBoxes.add(bounds);
                        if (!verified) inc("unverified_image_uses");
                        break;
                    case "W": case "W*": clip = true; if (imagesOnPage) inc("unverified_image_uses"); break;
                    case "BI": case "ID": case "EI": inc("unverified_image_uses"); break;
                    case "f": case "F": case "f*": case "B": case "B*": case "b": case "b*":
                    case "S": case "s": case "sh": case "Tj": case "TJ": case "'": case "\"":
                        // Later paint/text can conceal source pixels; keep complex image layouts partial.
                        if (imagesOnPage) inc("unverified_image_uses"); break;
                    case "BT": case "ET": case "Tf": case "Td": case "TD": case "Tm": case "T*":
                    case "Tc": case "Tw": case "Tz": case "TL": case "Ts": case "Tr":
                    case "m": case "l": case "c": case "v": case "y": case "h": case "re": case "n":
                    case "w": case "J": case "j": case "M": case "d": case "ri": case "i":
                    case "G": case "g": case "RG": case "rg": case "K": case "k": case "CS": case "cs":
                    case "SC": case "SCN": case "sc": case "scn": break;
                    default: inc("unsupported_operators");
                }
                operands.clear();
            }
            if (!operands.isEmpty() || !stack.isEmpty()) inc("unknown_structure");
        } finally { parser.close(); }
    }

    private void inspect(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) <= 0 || Files.size(path) > 25L * 1024 * 1024)
            throw new IOException();
        try (RandomAccessReadBufferedFile input = new RandomAccessReadBufferedFile(path.toString());
             PDDocument document = new PDFParser(input).parse(false)) {
            encrypted = document.isEncrypted();
            canExtract = document.getCurrentAccessPermission().canExtractContent();
            if (encrypted) reasons.add("encrypted_pdf");
            if (!canExtract) reasons.add("extraction_not_permitted");
            List<PDPage> originalPages = new ArrayList<>();
            int declared = document.getNumberOfPages();
            for (PDPage page : document.getPages()) {
                check(0);
                if (originalPages.size() >= MAX_PAGES) throw new Limit();
                originalPages.add(page);
                collectStreams(value(page.getCOSObject(), "Contents"));
                COSBase annotations = value(page.getCOSObject(), "Annots");
                if (annotations != null && annotations != COSNull.NULL) {
                    if (!(annotations instanceof COSArray)) inc("unknown_annotations");
                    else {
                        COSArray array = (COSArray)annotations;
                        if (array.size() > MAX_NODES) throw new Limit();
                        for (int i = 0; i < array.size(); i++) {
                            inc("annotations");
                            COSBase annotation = array.getObject(i);
                            if (!(annotation instanceof COSDictionary) || !ANNOTATION_TYPES.contains(name((COSDictionary)annotation, "Subtype"))) inc("unknown_annotations");
                        }
                    }
                }
            }
            pages = originalPages.size();
            if (pages < 1 || pages != declared) inc("unknown_structure");
            // Walk the trailer first so font streams can be classified before the xref sweep.
            COSDocument cos = document.getDocument();
            if (cos.getXrefTable().size() > MAX_NODES) throw new Limit();
            walk(cos.getTrailer(), 0, false);
            List<COSObjectKey> objectKeys = new ArrayList<>(cos.getXrefTable().keySet());
            for (COSObjectKey objectKey : objectKeys) walk(cos.getObjectFromPool(objectKey), 0, false);
            if (cos.getXrefTable().size() != objectKeys.size()) inc("unknown_structure");
            for (PDPage page : originalPages) pageContent(page);
            for (COSStream image : images) if (!usedImages.contains(image)) inc("unused_images");
            if (parserWarning) inc("parser_warnings");
            complete = true;
            status = "completed";
        }
    }

    private String json() {
        boolean absent = complete && Boolean.FALSE.equals(encrypted) && canExtract;
        for (Map.Entry<String, Integer> item : counts.entrySet()) {
            if (!Set.of("image_resources", "image_uses", "native_text_operations").contains(item.getKey()) && item.getValue() > 0) absent = false;
        }
        if (complete && !absent && reasons.isEmpty()) reasons.add("pdf_ancillary_content_unverified");
        StringBuilder out = new StringBuilder("{\"protocol\":\"pdf-features/v1\",\"status\":\"").append(status)
                .append("\",\"inventory_complete\":").append(complete).append(",\"original_page_count\":").append(pages)
                .append(",\"encrypted\":").append(encrypted).append(",\"can_extract\":").append(canExtract)
                .append(",\"ancillary_absent\":").append(absent).append(",\"feature_counts\":{");
        boolean first = true;
        for (Map.Entry<String, Integer> item : counts.entrySet()) {
            if (!first) out.append(','); first = false;
            out.append('"').append(item.getKey()).append("\":").append(item.getValue());
        }
        out.append("},\"reason_codes\":["); first = true;
        for (String reason : reasons) { if (!first) out.append(','); first = false; out.append('"').append(reason).append('"'); }
        return out.append("]}").toString();
    }

    public static void main(String[] args) {
        PrintStream result = System.out;
        // Suppress even unexpected library output; only the final fixed-schema result escapes.
        PrintStream discard = new PrintStream(OutputStream.nullOutputStream());
        System.setOut(discard); System.setErr(discard);
        PdfFeatures inspector = new PdfFeatures();
        try {
            quietLogging();
            if (args.length != 1) throw new IOException();
            inspector.inspect(Path.of(args[0]));
        } catch (InvalidPasswordException error) {
            inspector.encrypted = true;
            inspector.reasons.add("encrypted_pdf");
        } catch (Limit error) {
            inspector.status = "limited";
            inspector.reasons.add("pdf_feature_limit");
        } catch (Throwable error) {
            inspector.complete = false;
            inspector.status = "failed";
            inspector.reasons.add("pdf_feature_inspection_failed");
        }
        result.println(inspector.json());
    }
}
