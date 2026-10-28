import org.bouncycastle.crypto.digests.KeccakDigest;
import java.nio.charset.StandardCharsets;

/**
 * 用 FinalShell 自带 lib-run/bcprov.jar 里的 BouncyCastle 实现
 * 独立复算一遍 Keccak-384，验证我们 Python 实现与客户端算法完全一致。
 */
public class BcCheck {
    public static void main(String[] a) throws Exception {
        KeccakDigest d = new KeccakDigest(384);
        byte[] in = a.length > 0 ? a[0].getBytes(StandardCharsets.UTF_8) : new byte[0];
        d.update(in, 0, in.length);
        byte[] out = new byte[48];
        d.doFinal(out, 0);
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02x", b));
        String hex = sb.toString();
        System.out.println("input        = " + (a.length > 0 ? a[0] : "(empty)"));
        System.out.println("BC Keccak384 = " + hex);
        if (hex.length() >= 28) {
            System.out.println("[12:28]      = " + hex.substring(12, 28));
        }
    }
}
