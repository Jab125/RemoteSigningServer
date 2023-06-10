package com.jab125.signingserver;

import io.javalin.Javalin;
import io.javalin.http.HandlerType;
import jdk.security.jarsigner.JarSigner;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.zip.ZipFile;

public class Main {
    /**
     *
     * @param args [keystorePassword, certPassword, alias, signerName, jarSignerPassword]
     */
    public static void main(String[] args) {
        var javalin = Javalin.create();
        javalin.addHandler(HandlerType.POST, "/sign", ctx -> {
            SignatureMethod signatureMethod = SignatureMethod.valueOf(ctx.formParam("op"));
            if (signatureMethod == SignatureMethod.JARSIGN) {
                if (!ctx.formParam("key").equals(args[4])) {
                    ctx.status(403);
                    ctx.result(new byte[0]);
                    return;
                }
                var g = KeyStore.getInstance(Path.of("keystore.jks").toFile(), args[0].toCharArray());
                g.aliases().asIterator().forEachRemaining(System.out::println);
                var h = new JarSigner.Builder((KeyStore.PrivateKeyEntry) g.getEntry(args[2], new KeyStore.PasswordProtection(args[1].toCharArray())));
                var hhh = ctx.uploadedFile("file").getContent().readAllBytes();
                Path hi = Files.createTempFile(null, null);
                Files.write(hi,hhh);
                var output = Files.createTempFile(null, null);
                var hh = new FileOutputStream(output.toFile());
              //  System.setProperty("java.version", "RESERVED");
               // System.setProperty("java.vendor", "RESERVED");
                h.signerName(args[3]).build().sign(new ZipFile(hi.toFile()), hh);
                hh.close();
                ctx.result(new FileInputStream(output.toFile()));
            } else {
                ctx.status(500);
                ctx.result(new byte[0]);
            }
        });
        javalin.start(4000);
        System.out.println("Started server on port 4000");
    }
}
