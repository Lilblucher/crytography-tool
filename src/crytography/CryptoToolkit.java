package crytography;



import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;


public class CryptoToolkit {


    static final boolean COLOR = System.getenv("NO_COLOR") == null
            && (!System.getProperty("os.name").toLowerCase().contains("win") || System.getenv("WT_SESSION") != null);
    static final Scanner IN = new Scanner(System.in);
    static final SecureRandom RNG = new SecureRandom();
    static final List<String> LOG = new ArrayList<>();

    static String c(String code, String s) { return COLOR ? "\u001B[" + code + "m" + s + "\u001B[0m" : s; }
    static String bold(String s) { return c("1", s); }
    static String cyan(String s) { return c("36", s); }
    static String green(String s) { return c("32", s); }
    static String yellow(String s) { return c("33", s); }
    static String red(String s) { return c("31", s); }
    static String dim(String s) { return c("90", s); }
    static String rep(String s, int n) { StringBuilder b = new StringBuilder(); for (int i = 0; i < n; i++) b.append(s); return b.toString(); }

    static void banner() {
        System.out.println(cyan(bold(
                "\n  ____                  _        _____           _ _    _ _\n"
                + " / ___|_ __ _   _ _ __ | |_ ___ |_   _|__   ___ | | | _(_) |_\n"
                + "| |   | '__| | | | '_ \\| __/ _ \\  | |/ _ \\ / _ \\| | |/ / | __|\n"
                + "| |___| |  | |_| | |_) | || (_) | | | (_) | (_) | |   <| | |_\n"
                + " \\____|_|   \\__, | .__/ \\__\\___/  |_|\\___/ \\___/|_|_|\\_\\_|\\__|\n"
                + "            |___/|_|")));
        System.out.println(dim("  S-DES | RSA | ECC | SHA-256 | MD5     interactive edition by Lilblucher\n"));
    }

    static void header(String title) {
        System.out.println("\n" + cyan(rep("=", 60)));
        System.out.println(bold("  " + title));
        System.out.println(cyan(rep("=", 60)));
    }

    static void item(String key, String label) { System.out.println("  " + yellow("[" + key + "]") + " " + label); }

    static String ask(String label, String def) {
        System.out.print(yellow("? ") + label + (def != null ? dim(" [" + def + "]") : "") + ": ");
        System.out.flush();
        if (!IN.hasNextLine()) { System.out.println(); System.out.println("Bye."); System.exit(0); }
        String s = IN.nextLine().trim();
        return s.isEmpty() && def != null ? def : s;
    }

    static String menuChoice() { return ask("Choose", null); }

    static void info(String s) { System.out.println(dim("  " + s)); }
    static void ok(String s) { System.out.println(green("  [OK] ") + s); }
    static void err(String s) { System.out.println(red("  [X] " + s)); }

    static void out(String label, String value) {
        System.out.println("  " + bold(String.format("%-14s", label)) + green(value));
        LOG.add(label + ": " + value);
    }

    static void log(String s) { LOG.add("--- " + s); }

    static void pause() { ask("Press Enter to continue", ""); }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    static byte[] unhex(String s) {
        s = s.replaceAll("\\s+", "");
        if (s.length() % 2 != 0 || !s.matches("[0-9a-fA-F]*")) throw new IllegalArgumentException("Not valid hex");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String bin(int v, int width) {
        String s = Integer.toBinaryString(v);
        return rep("0", Math.max(0, width - s.length())) + s;
    }

    // =====================================================================
    //  1. S-DES
    // =====================================================================
    static class SDES {
        static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
        static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
        static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
        static final int[] IPI = {4, 1, 3, 5, 7, 2, 8, 6};
        static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
        static final int[] P4 = {2, 4, 3, 1};
        static final int[][] S0 = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
        static final int[][] S1 = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

        static String perm(String s, int[] t) {
            StringBuilder b = new StringBuilder();
            for (int i : t) b.append(s.charAt(i - 1));
            return b.toString();
        }

        static String ls(String s, int n) { return s.substring(n) + s.substring(0, n); }

        static String xor(String a, String b) {
            StringBuilder r = new StringBuilder();
            for (int i = 0; i < a.length(); i++) r.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
            return r.toString();
        }

        static String sbox(int[][] s, String x) {
            int row = Integer.parseInt("" + x.charAt(0) + x.charAt(3), 2);
            int col = Integer.parseInt("" + x.charAt(1) + x.charAt(2), 2);
            return bin(s[row][col], 2);
        }

        static String[] keys(String key, boolean verbose) {
            String p10 = perm(key, P10);
            String l1 = ls(p10.substring(0, 5), 1), r1 = ls(p10.substring(5), 1);
            String k1 = perm(l1 + r1, P8);
            String l2 = ls(l1, 2), r2 = ls(r1, 2);
            String k2 = perm(l2 + r2, P8);
            if (verbose) {
                System.out.println("  " + dim("key         ") + key);
                System.out.println("  " + dim("P10         ") + p10);
                System.out.println("  " + dim("LS-1 (L|R)  ") + l1 + " | " + r1);
                System.out.println("  " + dim("K1 = P8     ") + green(k1));
                System.out.println("  " + dim("LS-2 (L|R)  ") + l2 + " | " + r2);
                System.out.println("  " + dim("K2 = P8     ") + green(k2));
            }
            return new String[]{k1, k2};
        }

        static String fk(String b, String k, boolean verbose, String tag) {
            String l = b.substring(0, 4), r = b.substring(4);
            String ep = perm(r, EP);
            String x = xor(ep, k);
            String s0 = sbox(S0, x.substring(0, 4)), s1 = sbox(S1, x.substring(4));
            String p4 = perm(s0 + s1, P4);
            String res = xor(l, p4) + r;
            if (verbose) {
                System.out.println("  " + dim(tag + " E/P(R)=" + ep + "  xor K=" + x + "  S0,S1=" + s0 + "," + s1
                        + "  P4=" + p4 + "  ->  ") + green(res));
            }
            return res;
        }

        static String crypt(String block, String ka, String kb, boolean verbose) {
            String ip = perm(block, IP);
            if (verbose) System.out.println("  " + dim("IP           ") + ip);
            String r1 = fk(ip, ka, verbose, "fK1:");
            String sw = r1.substring(4) + r1.substring(0, 4);
            if (verbose) System.out.println("  " + dim("SW           ") + sw);
            String r2 = fk(sw, kb, verbose, "fK2:");
            String res = perm(r2, IPI);
            if (verbose) System.out.println("  " + dim("IP^-1        ") + green(res));
            return res;
        }

        static String encryptBlock(String block, String key, boolean verbose) {
            String[] k = keys(key, false);
            return crypt(block, k[0], k[1], verbose);
        }

        static String decryptBlock(String block, String key, boolean verbose) {
            String[] k = keys(key, false);
            return crypt(block, k[1], k[0], verbose);
        }

        static byte[] encryptBytes(byte[] data, String key, boolean cbc, String iv) {
            byte[] out = new byte[data.length];
            String prev = iv;
            for (int i = 0; i < data.length; i++) {
                String bits = bin(data[i] & 0xff, 8);
                if (cbc) bits = xor(bits, prev);
                String ct = encryptBlock(bits, key, false);
                prev = ct;
                out[i] = (byte) Integer.parseInt(ct, 2);
            }
            return out;
        }

        static byte[] decryptBytes(byte[] data, String key, boolean cbc, String iv) {
            byte[] out = new byte[data.length];
            String prev = iv;
            for (int i = 0; i < data.length; i++) {
                String ct = bin(data[i] & 0xff, 8);
                String pt = decryptBlock(ct, key, false);
                if (cbc) pt = xor(pt, prev);
                prev = ct;
                out[i] = (byte) Integer.parseInt(pt, 2);
            }
            return out;
        }
    }

    static String sdesKey = "1010000010";

    static String readBits(String label, int len, String def) {
        while (true) {
            String s = ask(label + " (" + len + " bits)", def);
            if (s.matches("[01]{" + len + "}")) return s;
            err("Enter exactly " + len + " binary digits (0/1).");
        }
    }

    static void sdesMenu() {
        while (true) {
            header("S-DES  -  Simplified DES");
            info("current key: " + sdesKey);
            item("1", "Set key (type or random)");
            item("2", "Show key schedule (K1, K2)");
            item("3", "Encrypt an 8-bit block (with round trace)");
            item("4", "Decrypt an 8-bit block (with round trace)");
            item("5", "Encrypt text  (ECB or CBC, hex output)");
            item("6", "Decrypt hex   (ECB or CBC)");
            item("0", "Back");
            String ch = menuChoice();
            try {
                switch (ch) {
                    case "1": {
                        String s = ask("Key (10 bits) or 'r' for random", "r");
                        if (s.equalsIgnoreCase("r")) sdesKey = bin(RNG.nextInt(1024), 10);
                        else if (s.matches("[01]{10}")) sdesKey = s;
                        else { err("Key must be 10 binary digits."); break; }
                        ok("Key set to " + sdesKey);
                        log("S-DES key set: " + sdesKey);
                        break;
                    }
                    case "2": {
                        String[] k = SDES.keys(sdesKey, true);
                        log("S-DES keys for " + sdesKey + ": K1=" + k[0] + " K2=" + k[1]);
                        break;
                    }
                    case "3": {
                        String pt = readBits("Plaintext block", 8, "10010111");
                        String ct = SDES.encryptBlock(pt, sdesKey, true);
                        out("Ciphertext", ct);
                        log("S-DES enc key=" + sdesKey + " pt=" + pt + " ct=" + ct);
                        break;
                    }
                    case "4": {
                        String ct = readBits("Ciphertext block", 8, "00111000");
                        String pt = SDES.decryptBlock(ct, sdesKey, true);
                        out("Plaintext", pt);
                        log("S-DES dec key=" + sdesKey + " ct=" + ct + " pt=" + pt);
                        break;
                    }
                    case "5": {
                        String text = ask("Text to encrypt", "HELLO");
                        boolean cbc = ask("Mode: (e)cb or (c)bc", "e").toLowerCase().startsWith("c");
                        String iv = cbc ? readBits("IV", 8, "10101010") : "";
                        byte[] ct = SDES.encryptBytes(text.getBytes(StandardCharsets.UTF_8), sdesKey, cbc, iv);
                        out("Ciphertext", hex(ct));
                        log("S-DES text enc (" + (cbc ? "CBC iv=" + iv : "ECB") + ") key=" + sdesKey);
                        break;
                    }
                    case "6": {
                        byte[] ct = unhex(ask("Hex ciphertext", null));
                        boolean cbc = ask("Mode: (e)cb or (c)bc", "e").toLowerCase().startsWith("c");
                        String iv = cbc ? readBits("IV", 8, "10101010") : "";
                        byte[] pt = SDES.decryptBytes(ct, sdesKey, cbc, iv);
                        out("Plaintext", new String(pt, StandardCharsets.UTF_8));
                        break;
                    }
                    case "0": return;
                    default: err("Unknown option.");
                }
            } catch (Exception e) {
                err(e.getMessage());
            }
        }
    }

    // =====================================================================
    //  2. RSA
    // =====================================================================
    static BigInteger rsaP, rsaQ, rsaN, rsaPhi, rsaE, rsaD;

    static void rsaCompute(BigInteger p, BigInteger q, BigInteger e) {
        rsaP = p; rsaQ = q; rsaN = p.multiply(q);
        rsaPhi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        rsaE = e; rsaD = e.modInverse(rsaPhi);
    }

    static void rsaShow() {
        if (rsaN == null) { err("No keys yet. Generate or enter them first."); return; }
        out("p", rsaP.toString());
        out("q", rsaQ.toString());
        out("n = p*q", rsaN.toString());
        out("phi(n)", rsaPhi.toString());
        out("e (public)", rsaE.toString());
        out("d (private)", rsaD.toString());
        info("public key = (e, n)   private key = (d, n)   modulus size = " + rsaN.bitLength() + " bits");
    }

    static boolean rsaReady() {
        if (rsaN == null) { err("No keys yet. Use option 1 or 2 first."); return false; }
        return true;
    }

    static BigInteger msgHash(byte[] msg) {
        return new BigInteger(1, Hash.sha256(msg)).mod(rsaN);
    }

    static void rsaMenu() {
        while (true) {
            header("RSA");
            info(rsaN == null ? "no keys loaded" : "keys loaded, n is " + rsaN.bitLength() + " bits");
            item("1", "Generate random keys");
            item("2", "Enter p, q, e manually (textbook mode)");
            item("3", "Show keys");
            item("4", "Encrypt text (public key, byte by byte)");
            item("5", "Decrypt numbers (private key)");
            item("6", "Sign a message (SHA-256 then private key)");
            item("7", "Verify a signature");
            item("0", "Back");
            String ch = menuChoice();
            try {
                switch (ch) {
                    case "1": {
                        int bits = Integer.parseInt(ask("Modulus size in bits (16 - 2048)", "64"));
                        if (bits < 16 || bits > 2048) { err("Pick a size from 16 to 2048."); break; }
                        BigInteger p, q, phi, e;
                        while (true) {
                            p = BigInteger.probablePrime(bits / 2, RNG);
                            q = BigInteger.probablePrime(bits - bits / 2, RNG);
                            if (p.equals(q)) continue;
                            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                            e = phi.compareTo(BigInteger.valueOf(65537)) > 0 ? BigInteger.valueOf(65537) : BigInteger.valueOf(3);
                            while (!e.gcd(phi).equals(BigInteger.ONE)) e = e.add(BigInteger.TWO);
                            if (e.compareTo(phi) < 0 && p.multiply(q).compareTo(BigInteger.valueOf(255)) > 0) break;
                        }
                        rsaCompute(p, q, e);
                        log("RSA keys generated (" + rsaN.bitLength() + " bits)");
                        rsaShow();
                        break;
                    }
                    case "2": {
                        BigInteger p = new BigInteger(ask("Prime p", "61"));
                        BigInteger q = new BigInteger(ask("Prime q", "53"));
                        if (!p.isProbablePrime(30) || !q.isProbablePrime(30)) { err("p and q must both be prime."); break; }
                        if (p.equals(q)) { err("p and q must be different."); break; }
                        if (p.multiply(q).compareTo(BigInteger.valueOf(255)) <= 0) { err("n = p*q must exceed 255 (one byte per block)."); break; }
                        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                        BigInteger e = new BigInteger(ask("Public exponent e", "17"));
                        if (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE)) {
                            err("e must satisfy 1 < e < phi(n) and gcd(e, phi) = 1  (phi = " + phi + ")."); break;
                        }
                        rsaCompute(p, q, e);
                        log("RSA keys entered manually");
                        rsaShow();
                        break;
                    }
                    case "3": rsaShow(); break;
                    case "4": {
                        if (!rsaReady()) break;
                        String text = ask("Text to encrypt", "HELLO");
                        byte[] data = text.getBytes(StandardCharsets.UTF_8);
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < data.length; i++) {
                            BigInteger m = BigInteger.valueOf(data[i] & 0xff);
                            BigInteger ct = m.modPow(rsaE, rsaN);
                            if (i < 3) info("m=" + m + "  ->  m^e mod n = " + ct);
                            sb.append(ct).append(' ');
                        }
                        out("Ciphertext", sb.toString().trim());
                        break;
                    }
                    case "5": {
                        if (!rsaReady()) break;
                        String[] parts = ask("Ciphertext numbers (space separated)", null).split("\\s+");
                        byte[] data = new byte[parts.length];
                        for (int i = 0; i < parts.length; i++) {
                            BigInteger m = new BigInteger(parts[i]).modPow(rsaD, rsaN);
                            if (m.compareTo(BigInteger.valueOf(255)) > 0) throw new IllegalArgumentException("Decrypted value out of byte range - wrong key?");
                            if (i < 3) info("c=" + parts[i] + "  ->  c^d mod n = " + m);
                            data[i] = (byte) m.intValue();
                        }
                        out("Plaintext", new String(data, StandardCharsets.UTF_8));
                        break;
                    }
                    case "6": {
                        if (!rsaReady()) break;
                        String msg = ask("Message to sign", "pay Tom 10");
                        BigInteger h = msgHash(msg.getBytes(StandardCharsets.UTF_8));
                        BigInteger sig = h.modPow(rsaD, rsaN);
                        info("SHA-256(message) mod n = " + h);
                        out("Signature", sig.toString());
                        if (rsaN.bitLength() < 256) info("note: n is smaller than a SHA-256 digest, so the hash is reduced mod n (demo only).");
                        break;
                    }
                    case "7": {
                        if (!rsaReady()) break;
                        String msg = ask("Message", "pay Tom 10");
                        BigInteger sig = new BigInteger(ask("Signature", null));
                        BigInteger expected = msgHash(msg.getBytes(StandardCharsets.UTF_8));
                        BigInteger recovered = sig.modPow(rsaE, rsaN);
                        info("sig^e mod n = " + recovered + "   hash = " + expected);
                        if (recovered.equals(expected)) ok("Signature VALID"); else err("Signature INVALID");
                        log("RSA verify -> " + recovered.equals(expected));
                        break;
                    }
                    case "0": return;
                    default: err("Unknown option.");
                }
            } catch (Exception e) {
                err(e.getMessage());
            }
        }
    }

    // =====================================================================
    //  3. ECC
    // =====================================================================
    static class Pt {
        final BigInteger x, y;
        Pt(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
        boolean inf() { return x == null; }
        static final Pt INF = new Pt(null, null);
        @Override public String toString() { return inf() ? "O (point at infinity)" : "(" + x + ", " + y + ")"; }
        String compact() { return inf() ? "O" : x.toString(16) + "," + y.toString(16); }
        @Override public boolean equals(Object o) {
            if (!(o instanceof Pt)) return false;
            Pt q = (Pt) o;
            if (inf() || q.inf()) return inf() && q.inf();
            return x.equals(q.x) && y.equals(q.y);
        }
        @Override public int hashCode() { return inf() ? 0 : x.hashCode() * 31 + y.hashCode(); }
    }

    static class Curve {
        final String name;
        final BigInteger p, a, b, n;
        final Pt g;
        Curve(String name, BigInteger p, BigInteger a, BigInteger b, Pt g, BigInteger n) {
            this.name = name; this.p = p; this.a = a; this.b = b; this.g = g; this.n = n;
        }

        boolean on(Pt q) {
            if (q.inf()) return true;
            BigInteger l = q.y.multiply(q.y).mod(p);
            BigInteger r = q.x.pow(3).add(a.multiply(q.x)).add(b).mod(p);
            return l.equals(r);
        }

        Pt add(Pt P, Pt Q) {
            if (P.inf()) return Q;
            if (Q.inf()) return P;
            BigInteger lam;
            if (P.x.equals(Q.x)) {
                if (!P.y.equals(Q.y) || P.y.signum() == 0) return Pt.INF;
                lam = P.x.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                        .multiply(P.y.shiftLeft(1).modInverse(p)).mod(p);
            } else {
                lam = Q.y.subtract(P.y).multiply(Q.x.subtract(P.x).mod(p).modInverse(p)).mod(p);
            }
            BigInteger x3 = lam.pow(2).subtract(P.x).subtract(Q.x).mod(p);
            BigInteger y3 = lam.multiply(P.x.subtract(x3)).subtract(P.y).mod(p);
            return new Pt(x3, y3);
        }

        Pt mul(BigInteger k, Pt P, boolean trace) {
            Pt R = Pt.INF;
            for (int i = k.bitLength() - 1; i >= 0; i--) {
                R = add(R, R);
                if (trace) System.out.println("  " + dim("bit " + (k.testBit(i) ? "1" : "0") + "  double -> ") + R);
                if (k.testBit(i)) {
                    R = add(R, P);
                    if (trace) System.out.println("  " + dim("       add P  -> ") + R);
                }
            }
            return R;
        }
    }

    static final Curve TOY = new Curve("toy curve  y^2 = x^3 + 2x + 2 (mod 17)",
            BigInteger.valueOf(17), BigInteger.TWO, BigInteger.TWO,
            new Pt(BigInteger.valueOf(5), BigInteger.ONE), BigInteger.valueOf(19));

    static final Curve SECP256K1 = new Curve("secp256k1  y^2 = x^3 + 7 (mod p), 256-bit",
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16),
            BigInteger.ZERO, BigInteger.valueOf(7),
            new Pt(new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                    new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)),
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16));

    static Curve curve = SECP256K1;
    static BigInteger eccD;
    static Pt eccQ;

    static BigInteger randomScalar(Curve cv) {
        BigInteger k;
        do { k = new BigInteger(cv.n.bitLength(), RNG); }
        while (k.signum() == 0 || k.compareTo(cv.n) >= 0);
        return k;
    }

    static Pt parsePt(String s) {
        String[] t = s.split(",");
        return new Pt(new BigInteger(t[0].trim(), 16), new BigInteger(t[1].trim(), 16));
    }

    static BigInteger digestToZ(byte[] msg) {
        BigInteger e = new BigInteger(1, Hash.sha256(msg));
        int extra = 256 - curve.n.bitLength();
        return extra > 0 ? e.shiftRight(extra) : e;
    }

    /** Keystream = SHA-256(shared.x || counter), XORed with data (ECIES-style, educational). */
    static byte[] eccStream(Pt shared, byte[] data) {
        byte[] out = new byte[data.length];
        byte[] xb = shared.x.toByteArray();
        for (int i = 0; i < data.length; i += 32) {
            byte[] seed = Arrays.copyOf(xb, xb.length + 1);
            seed[xb.length] = (byte) (i / 32);
            byte[] ks = Hash.sha256(seed);
            for (int j = 0; j < 32 && i + j < data.length; j++) out[i + j] = (byte) (data[i + j] ^ ks[j]);
        }
        return out;
    }

    static boolean eccKeysReady() {
        if (eccD == null) { err("No key pair yet. Use option 4 first."); return false; }
        return true;
    }

    static void eccMenu() {
        while (true) {
            header("ECC  -  Elliptic Curve Cryptography");
            info("curve: " + curve.name);
            item("1", "Switch curve (toy / secp256k1)");
            item("2", "Show curve parameters" + (curve == TOY ? " and list all points" : ""));
            item("3", "Point arithmetic  (k*G with trace, or aG + bG)");
            item("4", "Generate key pair");
            item("5", "ECDH key exchange (Tom <-> Bob)");
            item("6", "ECDSA sign");
            item("7", "ECDSA verify");
            item("8", "Encrypt text (ECIES-style, to the public key)");
            item("9", "Decrypt text (with the private key)");
            item("0", "Back");
            String ch = menuChoice();
            try {
                switch (ch) {
                    case "1":
                        curve = ask("Curve: (t)oy or (s)ecp256k1", "s").toLowerCase().startsWith("t") ? TOY : SECP256K1;
                        eccD = null; eccQ = null;
                        ok("Using " + curve.name + "  (key pair cleared)");
                        break;
                    case "2": {
                        out("p", curve.p.toString());
                        out("a", curve.a.toString());
                        out("b", curve.b.toString());
                        out("G", curve.g.toString());
                        out("n (order)", curve.n.toString());
                        if (curve == TOY) {
                            StringBuilder sb = new StringBuilder("O");
                            for (int x = 0; x < 17; x++)
                                for (int y = 0; y < 17; y++) {
                                    Pt q = new Pt(BigInteger.valueOf(x), BigInteger.valueOf(y));
                                    if (TOY.on(q)) sb.append("  (").append(x).append(",").append(y).append(")");
                                }
                            out("All points", sb.toString());
                        }
                        break;
                    }
                    case "3": {
                        String mode = ask("(m) k*G with trace, (a) add aG + bG", "m").toLowerCase();
                        if (mode.startsWith("a")) {
                            BigInteger a = new BigInteger(ask("a", "2")), b = new BigInteger(ask("b", "3"));
                            Pt A = curve.mul(a, curve.g, false), B = curve.mul(b, curve.g, false);
                            out("aG", A.toString());
                            out("bG", B.toString());
                            Pt S = curve.add(A, B);
                            out("aG + bG", S.toString());
                            out("(a+b)G", curve.mul(a.add(b), curve.g, false).toString());
                        } else {
                            BigInteger k = new BigInteger(ask("Scalar k", "7"));
                            boolean tr = k.bitLength() <= 20;
                            Pt R = curve.mul(k, curve.g, tr);
                            out("k*G", R.toString());
                            out("on curve?", String.valueOf(curve.on(R)));
                        }
                        break;
                    }
                    case "4": {
                        String s = ask("Private key d (decimal) or 'r' for random", "r");
                        eccD = s.equalsIgnoreCase("r") ? randomScalar(curve) : new BigInteger(s);
                        if (eccD.signum() <= 0 || eccD.compareTo(curve.n) >= 0) { eccD = null; err("d must be in 1 .. n-1."); break; }
                        eccQ = curve.mul(eccD, curve.g, false);
                        out("private d", eccD.toString());
                        out("public Q", eccQ.toString());
                        info("Q = d * G");
                        break;
                    }
                    case "5": {
                        BigInteger da = randomScalar(curve), db = randomScalar(curve);
                        Pt qa = curve.mul(da, curve.g, false), qb = curve.mul(db, curve.g, false);
                        out("Tom d", da.toString());
                        out("Tom Q", qa.toString());
                        out("Bob d", db.toString());
                        out("Bob Q", qb.toString());
                        Pt sa = curve.mul(da, qb, false), sb = curve.mul(db, qa, false);
                        out("Tom S", sa.toString());
                        out("Bob S", sb.toString());
                        if (sa.equals(sb)) ok("Both parties derived the same shared secret."); else err("Mismatch!");
                        if (!sa.inf()) out("SHA-256(S.x)", hex(Hash.sha256(sa.x.toByteArray())));
                        break;
                    }
                    case "6": {
                        if (!eccKeysReady()) break;
                        String msg = ask("Message to sign", "hello ecc");
                        BigInteger z = digestToZ(msg.getBytes(StandardCharsets.UTF_8));
                        BigInteger r, s;
                        while (true) {
                            BigInteger k = randomScalar(curve);
                            Pt R = curve.mul(k, curve.g, false);
                            if (R.inf()) continue;
                            r = R.x.mod(curve.n);
                            if (r.signum() == 0) continue;
                            s = k.modInverse(curve.n).multiply(z.add(r.multiply(eccD))).mod(curve.n);
                            if (s.signum() != 0) break;
                        }
                        out("Signature r", r.toString());
                        out("Signature s", s.toString());
                        log("ECDSA sign on " + curve.name);
                        break;
                    }
                    case "7": {
                        if (!eccKeysReady()) break;
                        String msg = ask("Message", "hello ecc");
                        BigInteger r = new BigInteger(ask("r", null)), s = new BigInteger(ask("s", null));
                        boolean valid = false;
                        if (r.signum() > 0 && r.compareTo(curve.n) < 0 && s.signum() > 0 && s.compareTo(curve.n) < 0) {
                            BigInteger z = digestToZ(msg.getBytes(StandardCharsets.UTF_8));
                            BigInteger w = s.modInverse(curve.n);
                            Pt P = curve.add(curve.mul(z.multiply(w).mod(curve.n), curve.g, false),
                                    curve.mul(r.multiply(w).mod(curve.n), eccQ, false));
                            valid = !P.inf() && P.x.mod(curve.n).equals(r);
                        }
                        if (valid) ok("Signature VALID"); else err("Signature INVALID");
                        log("ECDSA verify -> " + valid);
                        break;
                    }
                    case "8": {
                        if (!eccKeysReady()) break;
                        String text = ask("Text to encrypt", "HELLO");
                        BigInteger k = randomScalar(curve);
                        Pt R = curve.mul(k, curve.g, false);
                        Pt shared = curve.mul(k, eccQ, false);
                        if (shared.inf()) { err("Degenerate shared point, try again."); break; }
                        byte[] ct = eccStream(shared, text.getBytes(StandardCharsets.UTF_8));
                        out("Ephemeral R", R.compact());
                        out("Ciphertext", hex(ct));
                        info("Send both values. R = k*G, shared = k*Q.");
                        break;
                    }
                    case "9": {
                        if (!eccKeysReady()) break;
                        Pt R = parsePt(ask("Ephemeral R as 'x,y' (hex)", null));
                        if (!curve.on(R) || R.inf()) { err("R is not a valid point on this curve."); break; }
                        byte[] ct = unhex(ask("Ciphertext (hex)", null));
                        Pt shared = curve.mul(eccD, R, false);
                        out("Plaintext", new String(eccStream(shared, ct), StandardCharsets.UTF_8));
                        break;
                    }
                    case "0": return;
                    default: err("Unknown option.");
                }
            } catch (Exception e) {
                err(e.getMessage() == null ? e.toString() : e.getMessage());
            }
        }
    }

    // =====================================================================
    //  4. Hashing: SHA-256 and MD5, from scratch
    // =====================================================================
    static class Hash {
        static final int[] K256 = new int[64];
        static final int[] H256 = new int[8];
        static final int[] KMD5 = new int[64];
        static final int[] SMD5 = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

        static {
            int[] primes = new int[64];
            int cnt = 0;
            for (int n = 2; cnt < 64; n++) {
                boolean pr = true;
                for (int d = 2; d * d <= n; d++) if (n % d == 0) { pr = false; break; }
                if (pr) primes[cnt++] = n;
            }
            for (int i = 0; i < 64; i++) {
                double f = Math.cbrt(primes[i]);
                K256[i] = (int) (long) ((f - Math.floor(f)) * 4294967296.0);
                KMD5[i] = (int) (long) Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296.0);
            }
            for (int i = 0; i < 8; i++) {
                double f = Math.sqrt(primes[i]);
                H256[i] = (int) (long) ((f - Math.floor(f)) * 4294967296.0);
            }
        }

        static byte[] sha256(byte[] msg) {
            int len = msg.length;
            int total = ((len + 8) / 64 + 1) * 64;
            byte[] p = Arrays.copyOf(msg, total);
            p[len] = (byte) 0x80;
            long bits = (long) len * 8;
            for (int i = 0; i < 8; i++) p[total - 1 - i] = (byte) (bits >>> (8 * i));
            int[] h = H256.clone();
            int[] w = new int[64];
            for (int off = 0; off < total; off += 64) {
                for (int t = 0; t < 16; t++)
                    w[t] = (p[off + 4 * t] & 0xff) << 24 | (p[off + 4 * t + 1] & 0xff) << 16
                            | (p[off + 4 * t + 2] & 0xff) << 8 | (p[off + 4 * t + 3] & 0xff);
                for (int t = 16; t < 64; t++) {
                    int s0 = Integer.rotateRight(w[t - 15], 7) ^ Integer.rotateRight(w[t - 15], 18) ^ (w[t - 15] >>> 3);
                    int s1 = Integer.rotateRight(w[t - 2], 17) ^ Integer.rotateRight(w[t - 2], 19) ^ (w[t - 2] >>> 10);
                    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
                }
                int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
                for (int t = 0; t < 64; t++) {
                    int S1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                    int ch = (e & f) ^ (~e & g);
                    int t1 = hh + S1 + ch + K256[t] + w[t];
                    int S0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                    int maj = (a & b) ^ (a & c) ^ (b & c);
                    int t2 = S0 + maj;
                    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
                }
                h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
            }
            byte[] out = new byte[32];
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 4; j++) out[4 * i + j] = (byte) (h[i] >>> (24 - 8 * j));
            return out;
        }

        static byte[] md5(byte[] msg) {
            int len = msg.length;
            int total = ((len + 8) / 64 + 1) * 64;
            byte[] p = Arrays.copyOf(msg, total);
            p[len] = (byte) 0x80;
            long bits = (long) len * 8;
            for (int i = 0; i < 8; i++) p[total - 8 + i] = (byte) (bits >>> (8 * i));
            int a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
            int[] m = new int[16];
            for (int off = 0; off < total; off += 64) {
                for (int i = 0; i < 16; i++)
                    m[i] = (p[off + 4 * i] & 0xff) | (p[off + 4 * i + 1] & 0xff) << 8
                            | (p[off + 4 * i + 2] & 0xff) << 16 | (p[off + 4 * i + 3] & 0xff) << 24;
                int A = a0, B = b0, C = c0, D = d0;
                for (int i = 0; i < 64; i++) {
                    int F, g;
                    if (i < 16) { F = (B & C) | (~B & D); g = i; }
                    else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
                    else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
                    else { F = C ^ (B | ~D); g = (7 * i) % 16; }
                    F = F + A + KMD5[i] + m[g];
                    A = D; D = C; C = B;
                    B = B + Integer.rotateLeft(F, SMD5[i]);
                }
                a0 += A; b0 += B; c0 += C; d0 += D;
            }
            byte[] out = new byte[16];
            int[] r = {a0, b0, c0, d0};
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++) out[4 * i + j] = (byte) (r[i] >>> (8 * j));
            return out;
        }

        static byte[] lib(String alg, byte[] data) {
            try { return MessageDigest.getInstance(alg).digest(data); }
            catch (Exception e) { throw new RuntimeException(e); }
        }

        static int bitDiff(byte[] x, byte[] y) {
            int d = 0;
            for (int i = 0; i < x.length; i++) d += Integer.bitCount((x[i] ^ y[i]) & 0xff);
            return d;
        }
    }

    static void hashMenu() {
        while (true) {
            header("Hashing  -  SHA-256 and MD5");
            item("1", "Hash text with both algorithms");
            item("2", "Hash a file");
            item("3", "Verify integrity (compare with an expected hash)");
            item("4", "Avalanche effect (flip 1 bit, count changed bits)");
            item("5", "Cross-check my implementation against Java's MessageDigest");
            item("0", "Back");
            String ch = menuChoice();
            try {
                switch (ch) {
                    case "1": {
                        byte[] d = ask("Text", "abc").getBytes(StandardCharsets.UTF_8);
                        out("SHA-256", hex(Hash.sha256(d)));
                        out("MD5", hex(Hash.md5(d)));
                        break;
                    }
                    case "2": {
                        byte[] d = Files.readAllBytes(Paths.get(ask("File path", null)));
                        info(d.length + " bytes read");
                        out("SHA-256", hex(Hash.sha256(d)));
                        out("MD5", hex(Hash.md5(d)));
                        break;
                    }
                    case "3": {
                        byte[] d = ask("Text", "abc").getBytes(StandardCharsets.UTF_8);
                        boolean sha = ask("Algorithm: (s)ha256 or (m)d5", "s").toLowerCase().startsWith("s");
                        String expect = ask("Expected hash (hex)", null).toLowerCase().replaceAll("\\s", "");
                        String got = hex(sha ? Hash.sha256(d) : Hash.md5(d));
                        out("Computed", got);
                        if (got.equals(expect)) ok("MATCH - data is intact."); else err("MISMATCH - data was changed or hash is wrong.");
                        break;
                    }
                    case "4": {
                        byte[] d = ask("Text", "The quick brown fox").getBytes(StandardCharsets.UTF_8);
                        if (d.length == 0) { err("Enter at least one character."); break; }
                        byte[] e = d.clone();
                        e[0] ^= 1;
                        byte[] s1 = Hash.sha256(d), s2 = Hash.sha256(e), m1 = Hash.md5(d), m2 = Hash.md5(e);
                        info("original : " + new String(d, StandardCharsets.UTF_8));
                        info("flipped  : " + new String(e, StandardCharsets.UTF_8) + "   (lowest bit of first byte toggled)");
                        out("SHA-256 #1", hex(s1));
                        out("SHA-256 #2", hex(s2));
                        int ds = Hash.bitDiff(s1, s2), dm = Hash.bitDiff(m1, m2);
                        out("SHA-256 diff", ds + " of 256 bits changed (" + String.format("%.1f", ds / 2.56) + "%)");
                        out("MD5 #1", hex(m1));
                        out("MD5 #2", hex(m2));
                        out("MD5 diff", dm + " of 128 bits changed (" + String.format("%.1f", dm / 1.28) + "%)");
                        break;
                    }
                    case "5": selfTestHashOnly(); break;
                    case "0": return;
                    default: err("Unknown option.");
                }
            } catch (Exception e) {
                err(e.getMessage() == null ? e.toString() : e.getMessage());
            }
        }
    }

    // =====================================================================
    //  Self-test, demo, session export
    // =====================================================================
    static boolean check(String name, boolean cond) {
        if (cond) ok(name); else err("FAILED: " + name);
        return cond;
    }

    static boolean selfTestHashOnly() {
        boolean all = true;
        String[] samples = {"", "abc", "The quick brown fox jumps over the lazy dog", rep("a", 1000), rep("xyz", 77)};
        for (String s : samples) {
            byte[] d = s.getBytes(StandardCharsets.UTF_8);
            String label = s.length() > 20 ? s.substring(0, 17) + "..." : "\"" + s + "\"";
            all &= check("SHA-256 matches library for " + label, Arrays.equals(Hash.sha256(d), Hash.lib("SHA-256", d)));
            all &= check("MD5     matches library for " + label, Arrays.equals(Hash.md5(d), Hash.lib("MD5", d)));
        }
        return all;
    }

    static boolean selfTest() {
        header("Self-test (known answer vectors)");
        boolean all = true;
        String[] k = SDES.keys("1010000010", false);
        all &= check("S-DES K1 = 10100100, K2 = 01000011", k[0].equals("10100100") && k[1].equals("01000011"));
        all &= check("S-DES 10010111 -> 00111000", SDES.encryptBlock("10010111", "1010000010", false).equals("00111000"));
        all &= check("S-DES decrypt round trip", SDES.decryptBlock("00111000", "1010000010", false).equals("10010111"));
        BigInteger n = BigInteger.valueOf(61 * 53), e = BigInteger.valueOf(17), d = BigInteger.valueOf(2753);
        all &= check("RSA textbook 61/53/17: d = 2753", e.modInverse(BigInteger.valueOf(60 * 52)).equals(d));
        all &= check("RSA 65 -> 2790 -> 65", BigInteger.valueOf(65).modPow(e, n).equals(BigInteger.valueOf(2790))
                && BigInteger.valueOf(2790).modPow(d, n).equals(BigInteger.valueOf(65)));
        Pt twoG = SECP256K1.mul(BigInteger.TWO, SECP256K1.g, false);
        all &= check("ECC secp256k1 2G has the published x coordinate",
                twoG.x.equals(new BigInteger("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16)));
        all &= check("ECC secp256k1 n*G = infinity", SECP256K1.mul(SECP256K1.n, SECP256K1.g, false).inf());
        all &= check("ECC toy 19*G = infinity", TOY.mul(BigInteger.valueOf(19), TOY.g, false).inf());
        all &= check("SHA-256(\"abc\") = ba7816bf...15ad",
                hex(Hash.sha256("abc".getBytes(StandardCharsets.UTF_8))).equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        all &= check("MD5(\"abc\") = 90015098...72",
                hex(Hash.md5("abc".getBytes(StandardCharsets.UTF_8))).equals("900150983cd24fb0d6963f7d28e17f72"));
        all &= selfTestHashOnly();
        System.out.println();
        if (all) ok(bold("All tests passed.")); else err("Some tests failed.");
        return all;
    }

    static void demo() {
        header("Guided demo - all four algorithms working together");
        String message = "Meet at 9";
        byte[] mb = message.getBytes(StandardCharsets.UTF_8);
        System.out.println(bold("\n  Step 1  Hash the message"));
        out("Message", message);
        out("SHA-256", hex(Hash.sha256(mb)));
        out("MD5", hex(Hash.md5(mb)));

        System.out.println(bold("\n  Step 2  ECC key agreement (secp256k1 ECDH)"));
        Curve cv = SECP256K1;
        BigInteger da = randomScalar(cv), db = randomScalar(cv);
        Pt qa = cv.mul(da, cv.g, false), qb = cv.mul(db, cv.g, false);
        Pt sa = cv.mul(da, qb, false), sb = cv.mul(db, qa, false);
        check("Tom and Bob derived the same secret", sa.equals(sb));
        byte[] digest = Hash.sha256(sa.x.toByteArray());
        String key = bin(((digest[0] & 0xff) << 2) | ((digest[1] & 0xff) >> 6), 10);
        out("S-DES key", key + "   (first 10 bits of SHA-256 of the shared secret)");

        System.out.println(bold("\n  Step 3  S-DES encrypts the message with that key"));
        byte[] ct = SDES.encryptBytes(mb, key, true, "10101010");
        out("Ciphertext", hex(ct));
        String back = new String(SDES.decryptBytes(ct, key, true, "10101010"), StandardCharsets.UTF_8);
        check("Bob decrypts: \"" + back + "\"", back.equals(message));

        System.out.println(bold("\n  Step 4  RSA signs the SHA-256 digest, then verifies"));
        BigInteger p = BigInteger.probablePrime(256, RNG), q = BigInteger.probablePrime(256, RNG);
        BigInteger rn = p.multiply(q), phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger re = BigInteger.valueOf(65537), rd = re.modInverse(phi);
        BigInteger h = new BigInteger(1, Hash.sha256(mb)).mod(rn);
        BigInteger sig = h.modPow(rd, rn);
        out("Signature", sig.toString(16).substring(0, 40) + "...");
        check("Signature verifies", sig.modPow(re, rn).equals(h));
        log("Guided demo executed");
        System.out.println();
    }

    static void exportLog() {
        if (LOG.isEmpty()) { err("Nothing to export yet. Run some operations first."); return; }
        String path = ask("Save to file", "crypto_session.txt");
        try {
            Files.write(Paths.get(path), String.join(System.lineSeparator(), LOG).getBytes(StandardCharsets.UTF_8));
            ok("Saved " + LOG.size() + " lines to " + path);
        } catch (Exception e) {
            err("Could not write file: " + e.getMessage());
        }
    }

    static void viewLog() {
        header("Session history");
        if (LOG.isEmpty()) info("(empty)");
        for (String l : LOG) System.out.println("  " + dim(l));
    }

    // =====================================================================
    //  Entry points
    // =====================================================================
    static void help() {
        System.out.println("Usage:");
        System.out.println("  java CryptoToolkit                          interactive menu");
        System.out.println("  java CryptoToolkit demo                     guided demo of all algorithms");
        System.out.println("  java CryptoToolkit selftest                 run known-answer tests");
        System.out.println("  java CryptoToolkit hash <sha256|md5> <text> hash text");
        System.out.println("  java CryptoToolkit sdes <enc|dec> <10-bit key> <8-bit block>");
    }

    static int cli(String[] a) {
        switch (a[0]) {
            case "demo": demo(); return 0;
            case "selftest": return selfTest() ? 0 : 1;
            case "hash":
                if (a.length < 3) { help(); return 2; }
                byte[] d = a[2].getBytes(StandardCharsets.UTF_8);
                System.out.println(hex(a[1].equalsIgnoreCase("md5") ? Hash.md5(d) : Hash.sha256(d)));
                return 0;
            case "sdes":
                if (a.length < 4 || !a[2].matches("[01]{10}") || !a[3].matches("[01]{8}")) { help(); return 2; }
                System.out.println(a[1].equals("dec") ? SDES.decryptBlock(a[3], a[2], false) : SDES.encryptBlock(a[3], a[2], false));
                return 0;
            default: help(); return a[0].equals("help") ? 0 : 2;
        }
    }

    public static void main(String[] args) {
        if (args.length > 0) System.exit(cli(args));
        banner();
        while (true) {
            header("MAIN MENU");
            item("1", "S-DES");
            item("2", "RSA");
            item("3", "ECC");
            item("4", "Hashing (SHA-256, MD5)");
            item("5", "Guided demo (all algorithms together)");
            item("6", "Self-test");
            item("7", "View session history");
            item("8", "Export session history to a file");
            item("0", "Exit");
            switch (menuChoice()) {
                case "1": sdesMenu(); break;
                case "2": rsaMenu(); break;
                case "3": eccMenu(); break;
                case "4": hashMenu(); break;
                case "5": demo(); pause(); break;
                case "6": selfTest(); pause(); break;
                case "7": viewLog(); pause(); break;
                case "8": exportLog(); break;
                case "0": System.out.println("Bye."); return;
                default: err("Unknown option.");
            }
        }
    }
}