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
package org.apache.xml.security.test.dom.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * A DocumentBuilder created from a DocumentBuilderFactory that a thread context class loader
 * supplies must not be handed out to parses running under another context class loader.
 */
public class DocumentBuilderClassLoaderTest extends org.junit.Assert {

    private static final String SERVICE = "META-INF/services/javax.xml.parsers.DocumentBuilderFactory";

    private static final AtomicInteger STUB_PARSES = new AtomicInteger();

    private static volatile String delegateFactoryClassName;

    @org.junit.Test
    public void builderFromOneContextClassLoaderIsNotReusedUnderAnother() throws Exception {
        delegateFactoryClassName = DocumentBuilderFactory.newInstance().getClass().getName();
        ClassLoader parent = getClass().getClassLoader();
        ClassLoader stubbing = new ServiceOverridingClassLoader(parent, writeServiceFile());
        ClassLoader plain = new ClassLoader(parent) { };

        Thread thread = Thread.currentThread();
        ClassLoader original = thread.getContextClassLoader();
        try {
            thread.setContextClassLoader(stubbing);
            parse();
            int stubParses = STUB_PARSES.get();
            assertTrue("the stub factory's builder was not used under its own loader", stubParses > 0);

            thread.setContextClassLoader(plain);
            parse();
            assertEquals("parses by the stub factory's builder after switching loaders", stubParses, STUB_PARSES.get());
        } finally {
            thread.setContextClassLoader(original);
        }
    }

    private static void parse() throws Exception {
        XMLSignatureInput input = new XMLSignatureInput("<a><b/></a>".getBytes("UTF-8"));
        assertFalse(input.getNodeSet().isEmpty());
    }

    private static URL writeServiceFile() throws IOException {
        File file = File.createTempFile("documentbuilderfactory", ".services");
        file.deleteOnExit();
        OutputStream out = new FileOutputStream(file);
        try {
            out.write(RecordingDocumentBuilderFactory.class.getName().getBytes("UTF-8"));
        } finally {
            out.close();
        }
        return file.toURI().toURL();
    }

    private static final class ServiceOverridingClassLoader extends ClassLoader {

        private final URL serviceFile;

        ServiceOverridingClassLoader(ClassLoader parent, URL serviceFile) {
            super(parent);
            this.serviceFile = serviceFile;
        }

        // The parent's own provider files (xercesImpl's) must stay hidden, or the lookup may pick them first.
        @Override
        public Enumeration<URL> getResources(String name) throws IOException {
            if (SERVICE.equals(name)) {
                return Collections.enumeration(Collections.singletonList(serviceFile));
            }
            return super.getResources(name);
        }

        @Override
        public URL getResource(String name) {
            if (SERVICE.equals(name)) {
                return serviceFile;
            }
            return super.getResource(name);
        }
    }

    public static final class RecordingDocumentBuilderFactory extends DocumentBuilderFactory {

        private final DocumentBuilderFactory delegate = DocumentBuilderFactory.newInstance(
            delegateFactoryClassName, RecordingDocumentBuilderFactory.class.getClassLoader());

        @Override
        public DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
            delegate.setNamespaceAware(isNamespaceAware());
            delegate.setValidating(isValidating());
            return new RecordingDocumentBuilder(delegate.newDocumentBuilder());
        }

        @Override
        public void setAttribute(String name, Object value) {
            delegate.setAttribute(name, value);
        }

        @Override
        public Object getAttribute(String name) {
            return delegate.getAttribute(name);
        }

        @Override
        public void setFeature(String name, boolean value) throws ParserConfigurationException {
            delegate.setFeature(name, value);
        }

        @Override
        public boolean getFeature(String name) throws ParserConfigurationException {
            return delegate.getFeature(name);
        }
    }

    private static final class RecordingDocumentBuilder extends DocumentBuilder {

        private final DocumentBuilder delegate;

        RecordingDocumentBuilder(DocumentBuilder delegate) {
            this.delegate = delegate;
        }

        @Override
        public Document parse(InputSource is) throws SAXException, IOException {
            STUB_PARSES.incrementAndGet();
            return delegate.parse(is);
        }

        @Override
        public void reset() {
            delegate.reset();
        }

        @Override
        public boolean isNamespaceAware() {
            return delegate.isNamespaceAware();
        }

        @Override
        public boolean isValidating() {
            return delegate.isValidating();
        }

        @Override
        public void setEntityResolver(EntityResolver er) {
            delegate.setEntityResolver(er);
        }

        @Override
        public void setErrorHandler(ErrorHandler eh) {
            delegate.setErrorHandler(eh);
        }

        @Override
        public Document newDocument() {
            return delegate.newDocument();
        }

        @Override
        public DOMImplementation getDOMImplementation() {
            return delegate.getDOMImplementation();
        }
    }
}
