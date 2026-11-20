// W7, part 2: draws a WireGuard configuration's QR code as a PNG for the emulator check of the import
// (scripts/verify-wireguard-import.sh), with ZXing's core library, the same jar the app builds with, which the check
// takes from Gradle's cache after checking its SHA-256 against android/gradle/verification-metadata.xml. Run as a
// single-file program: java -cp core-3.5.4.jar QrPicture.java TEXT-FILE OUT.png [scale]
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import javax.imageio.ImageIO;

public class QrPicture {
    public static void main(String[] args) throws Exception {
        String text = new String(Files.readAllBytes(new File(args[0]).toPath()), StandardCharsets.UTF_8);
        int scale = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        // As WireGuard's app draws its codes: bytes, no character-set header, level M, a margin of four modules.
        BitMatrix matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0,
            Map.of(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M, EncodeHintType.MARGIN, 4));
        BufferedImage image = new BufferedImage(matrix.getWidth() * scale, matrix.getHeight() * scale, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                image.setRGB(x, y, matrix.get(x / scale, y / scale) ? 0x000000 : 0xffffff);
            }
        }
        ImageIO.write(image, "png", new File(args[1]));
    }
}
