/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package javax.xml.crypto.test.dsig;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureMethod;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SigningKeyLoggingTest {

    static {
        Security.insertProviderAt(new XMLDSigRI(), 1);
    }

    @Test
    public void testGeneratedKeyIsNotLoggedWhenSigning() throws Exception {
        PrivateKey privateKey = generateKey();

        List<String> messages = signWithDebugLogging(privateKey);

        assertTrue("debug logging was not captured", containsText(messages, "JCA Algorithm"));
        assertFalse("private key appears in the debug log", containsText(messages, privateKey.toString()));
    }

    @Test
    public void testKeyMaterialIsNotLoggedWhenSigning() throws Exception {
        RSAPrivateKey key = (RSAPrivateKey) generateKey();
        String privateExponent = key.getPrivateExponent().toString();

        List<String> messages = signWithDebugLogging(new PrintsItsSecretKey(key));

        assertTrue("debug logging was not captured", containsText(messages, "JCA Algorithm"));
        assertFalse("private exponent appears in the debug log", containsText(messages, privateExponent));
    }

    private static PrivateKey generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair().getPrivate();
    }

    private static List<String> signWithDebugLogging(PrivateKey privateKey) throws Exception {
        final List<String> messages = Collections.synchronizedList(new ArrayList<String>());
        AppenderSkeleton appender = new AppenderSkeleton() {
            @Override
            protected void append(LoggingEvent event) {
                messages.add(event.getRenderedMessage());
            }

            @Override
            public void close() {
            }

            @Override
            public boolean requiresLayout() {
                return false;
            }
        };

        Logger logger = Logger.getLogger(DOMSignatureMethod.class);
        Level level = logger.getLevel();
        boolean additivity = logger.getAdditivity();
        logger.setLevel(Level.DEBUG);
        logger.setAdditivity(false);
        logger.addAppender(appender);
        try {
            sign(privateKey);
        } finally {
            logger.removeAppender(appender);
            logger.setAdditivity(additivity);
            logger.setLevel(level);
        }
        return messages;
    }

    private static void sign(PrivateKey privateKey) throws Exception {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
        Reference reference = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null),
            Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
            null, null);
        SignedInfo signedInfo = factory.newSignedInfo(
            factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
            Collections.singletonList(reference));
        XMLSignature signature = factory.newXMLSignature(signedInfo, null);

        Document document = XMLUtils.createDocumentBuilder(false).newDocument();
        Element root = document.createElementNS(null, "root");
        document.appendChild(root);
        signature.sign(new DOMSignContext(privateKey, root));
    }

    private static boolean containsText(List<String> messages, String text) {
        for (String message : messages) {
            if (message.contains(text)) {
                return true;
            }
        }
        return false;
    }

    // Do not swap this for a generated key: what a key's toString prints depends on
    // the JDK and provider, and those measured here print no secret.
    private static final class PrintsItsSecretKey implements RSAPrivateKey {
        private static final long serialVersionUID = 1L;

        private final transient RSAPrivateKey key;

        PrintsItsSecretKey(RSAPrivateKey key) {
            this.key = key;
        }

        @Override
        public BigInteger getPrivateExponent() {
            return key.getPrivateExponent();
        }

        @Override
        public BigInteger getModulus() {
            return key.getModulus();
        }

        @Override
        public String getAlgorithm() {
            return key.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return key.getFormat();
        }

        @Override
        public byte[] getEncoded() {
            return key.getEncoded();
        }

        @Override
        public String toString() {
            return "private exponent: " + key.getPrivateExponent();
        }
    }
}
