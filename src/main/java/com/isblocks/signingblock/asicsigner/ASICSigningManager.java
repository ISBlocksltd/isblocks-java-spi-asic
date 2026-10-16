package com.isblocks.signingblock.asicsigner;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.isblocks.bootifulmongodb.model.ObjectData;
import com.isblocks.signedblock.api.SignedBlockException;
import com.isblocks.signedblock.api.SignedBlockManager;
import com.isblocks.signingblock.cmssigner.CMSSigningManager;

public class ASICSigningManager implements SignedBlockManager {

    private static final String DEFAULT_PROPERTY = "ASiC-S";
    private static final String ASICS_MIMETYPE_VALUE = "application/vnd.etsi.asic-s+zip";
    private static final String ASICE_MIMETYPE_VALUE = "application/vnd.etsi.asic-e+zip";
    private static final String DATA_ENTRY_PREFIX = "payloads/";
    private static final String META_INF_DIRECTORY = "META-INF/";
    private static final String SIGNATURE_ENTRY = "META-INF/signatures.p7s";
    private static final String MANIFEST_ENTRY = "META-INF/manifest.xml";
    private static final String MANIFEST_NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

    private final CMSSigningManager cmsSigningManager = new CMSSigningManager();

    private ObjectData asicObject;
    private byte[] contentBytes;
    private byte[] signedBytes;
    private String algorithm;
    private String property;
    private String archiveEntryName;
    private List<AsicPayloadEntry> payloadEntries = new ArrayList<AsicPayloadEntry>();

    @Override
    public byte[] getBytesToSign(byte[] data) throws SignedBlockException {
        throw new SignedBlockException("ASiC signing requires a constraint and payload");
    }

    @Override
    public byte[] getBytesToSign(ObjectData asicObject) throws SignedBlockException {
        try {
            if (asicObject == null || asicObject.getAttributes() == null) {
                throw new SignedBlockException("ASiC signing object is required");
            }
            String encodedData = asicObject.getAttributes().get("data");
            if (encodedData == null || encodedData.isBlank()) {
                throw new SignedBlockException("Attribute 'data' is required");
            }
            return getBytesToSign(asicObject, Base64.getDecoder().decode(encodedData));
        } catch (SignedBlockException e) {
            throw e;
        } catch (Exception e) {
            throw new SignedBlockException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] getBytesToSign(ObjectData constraint, byte[] data) throws SignedBlockException {
        try {
            if (constraint == null || constraint.getAttributes() == null) {
                throw new SignedBlockException("ASiC signing constraint is required");
            }
            if (data == null || data.length == 0) {
                throw new SignedBlockException("ASiC data to sign is required");
            }

            this.asicObject = constraint;
            this.contentBytes = data;
            this.algorithm = constraint.getAttributes().get("algorithm");
            this.property = constraint.getAttributes().get("property");
            this.payloadEntries = resolvePayloadEntries(data);
            this.archiveEntryName = this.payloadEntries.get(0).entryName;

            String resolvedProperty = this.property == null || this.property.isBlank() ? DEFAULT_PROPERTY : this.property;
            if (!"ASIC-S".equalsIgnoreCase(resolvedProperty) && !"ASIC-E".equalsIgnoreCase(resolvedProperty)
                    && !"ASiC-S".equalsIgnoreCase(resolvedProperty) && !"ASiC-E".equalsIgnoreCase(resolvedProperty)) {
                throw new SignedBlockException("Unsupported ASiC property: " + resolvedProperty + ". Supported values: ASiC-S, ASiC-E");
            }

            byte[] bytesForCmsSignature = buildPayloadDigestInput();
            ObjectData cmsConstraint = createCmsConstraint(constraint, bytesForCmsSignature);
            return this.cmsSigningManager.getBytesToSign(cmsConstraint, bytesForCmsSignature);
        } catch (SignedBlockException e) {
            throw e;
        } catch (Exception e) {
            throw new SignedBlockException(e.getMessage(), e);
        }
    }

    @Override
    public void setSignature(ObjectData signature) throws SignedBlockException {
        try {
            if (signature == null || signature.getAttributes() == null) {
                throw new SignedBlockException("Signature object is required");
            }
            String encodedSignature = signature.getAttributes().get("signature");
            if (encodedSignature == null || encodedSignature.isBlank()) {
                throw new SignedBlockException("Attribute 'signature' is required");
            }
            this.signedBytes = Base64.getDecoder().decode(encodedSignature);
            this.cmsSigningManager.setSignature(signature);
        } catch (SignedBlockException e) {
            throw e;
        } catch (Exception e) {
            throw new SignedBlockException(e.getMessage(), e);
        }
    }

    @Override
    public ObjectData getSignedData() throws SignedBlockException {
        try {
            if (this.contentBytes == null || this.contentBytes.length == 0) {
                throw new SignedBlockException("getBytesToSign must be called before getSignedData");
            }
            if (this.signedBytes == null || this.signedBytes.length == 0) {
                throw new SignedBlockException("Signature has not been set");
            }

            ObjectData cmsSignedData = this.cmsSigningManager.getSignedData();
            String cmsBase64 = cmsSignedData != null && cmsSignedData.getAttributes() != null
                    ? cmsSignedData.getAttributes().get("data")
                    : null;
            if (cmsBase64 == null || cmsBase64.isBlank()) {
                throw new SignedBlockException("CMS signed data is missing");
            }

            byte[] asicBytes = buildAsicContainer(Base64.getDecoder().decode(cmsBase64));

            ObjectData result = new ObjectData();
            Map<String, String> attributes = new HashMap<String, String>();
            if (this.asicObject != null && this.asicObject.getAttributes() != null) {
                attributes.putAll(this.asicObject.getAttributes());
            }
            if (cmsSignedData != null && cmsSignedData.getAttributes() != null) {
                attributes.putAll(cmsSignedData.getAttributes());
            }
            attributes.put("data", Base64.getEncoder().encodeToString(asicBytes));
            attributes.put("format", "ASiC");
            attributes.put("containerType", normalizeProperty(this.property));
            attributes.put("mimeType", resolveContainerMimeType());
            attributes.put("payloadEntryName", this.archiveEntryName);
            attributes.put("embeddedCmsSignature", cmsBase64);
            result.setType("signedData");
            result.setAttributes(attributes);
            return result;
        } catch (SignedBlockException e) {
            throw e;
        } catch (Exception e) {
            throw new SignedBlockException(e.getMessage(), e);
        }
    }

    private ObjectData createCmsConstraint(ObjectData constraint, byte[] data) {
        ObjectData cmsConstraint = new ObjectData();
        Map<String, String> attributes = new HashMap<String, String>();
        if (constraint.getAttributes() != null) {
            attributes.putAll(constraint.getAttributes());
        }
        attributes.put("data", Base64.getEncoder().encodeToString(data));
        attributes.put("property", "CAdES");
        cmsConstraint.setAttributes(attributes);
        return cmsConstraint;
    }

    private byte[] buildAsicContainer(byte[] cmsSignature) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream, StandardCharsets.UTF_8);

        addStoredEntry(zipOutputStream, "mimetype", resolveContainerMimeType().getBytes(StandardCharsets.UTF_8));
        addDirectoryEntry(zipOutputStream, META_INF_DIRECTORY);
        for (AsicPayloadEntry payloadEntry : this.payloadEntries) {
            addDeflatedEntry(zipOutputStream, payloadEntry.entryName, payloadEntry.content);
        }
        addDeflatedEntry(zipOutputStream, SIGNATURE_ENTRY, cmsSignature);
        addDeflatedEntry(zipOutputStream, MANIFEST_ENTRY, buildManifest().getBytes(StandardCharsets.UTF_8));

        zipOutputStream.finish();
        zipOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    private void addStoredEntry(ZipOutputStream zipOutputStream, String entryName, byte[] content) throws Exception {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(content);
        ZipEntry zipEntry = new ZipEntry(entryName);
        zipEntry.setMethod(ZipEntry.STORED);
        zipEntry.setSize(content.length);
        zipEntry.setCompressedSize(content.length);
        zipEntry.setCrc(crc32.getValue());
        zipOutputStream.putNextEntry(zipEntry);
        zipOutputStream.write(content);
        zipOutputStream.closeEntry();
    }

    private void addDeflatedEntry(ZipOutputStream zipOutputStream, String entryName, byte[] content) throws Exception {
        ZipEntry zipEntry = new ZipEntry(entryName);
        zipOutputStream.putNextEntry(zipEntry);
        zipOutputStream.write(content);
        zipOutputStream.closeEntry();
    }

    private void addDirectoryEntry(ZipOutputStream zipOutputStream, String entryName) throws Exception {
        ZipEntry zipEntry = new ZipEntry(entryName.endsWith("/") ? entryName : entryName + "/");
        zipOutputStream.putNextEntry(zipEntry);
        zipOutputStream.closeEntry();
    }

    private String buildManifest() {
        String containerMimeType = resolveContainerMimeType();
        StringBuilder manifestBuilder = new StringBuilder();
        manifestBuilder.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        manifestBuilder.append("<manifest:manifest xmlns:manifest=\"").append(MANIFEST_NS).append("\">");
        manifestBuilder.append("<manifest:file-entry manifest:full-path=\"/\" manifest:version=\"1.2\" manifest:media-type=\"")
                .append(containerMimeType)
                .append("\"/>");
        manifestBuilder.append("<manifest:file-entry manifest:full-path=\"mimetype\" manifest:media-type=\"text/plain\"/>");
        manifestBuilder.append("<manifest:file-entry manifest:full-path=\"")
                .append(META_INF_DIRECTORY)
                .append("\" manifest:media-type=\"application/vnd.etsi.asic-meta\"/>");
        for (AsicPayloadEntry payloadEntry : this.payloadEntries) {
            manifestBuilder.append("<manifest:file-entry manifest:full-path=\"")
                    .append(payloadEntry.entryName)
                    .append("\" manifest:media-type=\"")
                    .append(payloadEntry.mimeType)
                    .append("\"/>");
        }
        manifestBuilder.append("<manifest:file-entry manifest:full-path=\"")
                .append(SIGNATURE_ENTRY)
                .append("\" manifest:media-type=\"application/pkcs7-signature\"/>");
        manifestBuilder.append("<manifest:file-entry manifest:full-path=\"")
                .append(MANIFEST_ENTRY)
                .append("\" manifest:media-type=\"text/xml\"/>");
        manifestBuilder.append("</manifest:manifest>");
        return manifestBuilder.toString();
    }

    private List<AsicPayloadEntry> resolvePayloadEntries(byte[] singlePayloadData) throws SignedBlockException {
        String filesValue = this.asicObject != null && this.asicObject.getAttributes() != null
                ? this.asicObject.getAttributes().get("files")
                : null;
        if (filesValue == null || filesValue.isBlank()) {
            List<AsicPayloadEntry> singleEntryList = new ArrayList<AsicPayloadEntry>();
            singleEntryList.add(new AsicPayloadEntry(resolveSingleArchiveEntryName(), resolvePayloadMimeType(), singlePayloadData));
            return singleEntryList;
        }

        try {
            String decodedFiles = new String(Base64.getDecoder().decode(filesValue), StandardCharsets.UTF_8);
            List<AsicPayloadEntry> parsedEntries = new ArrayList<AsicPayloadEntry>();
            String[] fileDefinitions = decodedFiles.split("\\r?\\n");
            for (String fileDefinition : fileDefinitions) {
                if (fileDefinition == null || fileDefinition.isBlank()) {
                    continue;
                }
                String[] parts = fileDefinition.split("\\|", 3);
                if (parts.length < 2) {
                    throw new SignedBlockException("Invalid ASiC files entry format. Expected name|base64Data|mimeType");
                }
                String entryName = sanitizePayloadEntryName(parts[0]);
                byte[] entryContent = Base64.getDecoder().decode(parts[1]);
                String mimeType = parts.length == 3 && parts[2] != null && !parts[2].isBlank()
                        ? parts[2]
                        : "application/octet-stream";
                parsedEntries.add(new AsicPayloadEntry(DATA_ENTRY_PREFIX + entryName, mimeType, entryContent));
            }
            if (parsedEntries.isEmpty()) {
                throw new SignedBlockException("ASiC-E requires at least one payload entry");
            }
            return parsedEntries;
        } catch (IllegalArgumentException e) {
            throw new SignedBlockException("Attribute 'files' must be Base64 encoded text containing name|base64Data|mimeType lines", e);
        }
    }

    private String resolveSingleArchiveEntryName() {
        String requestedName = this.asicObject != null && this.asicObject.getAttributes() != null
                ? this.asicObject.getAttributes().get("fileName")
                : null;
        return DATA_ENTRY_PREFIX + sanitizePayloadEntryName(requestedName);
    }

    private String sanitizePayloadEntryName(String requestedName) {
        String sanitized = requestedName == null || requestedName.isBlank()
                ? "document-" + UUID.randomUUID() + ".bin"
                : requestedName;
        while (sanitized.startsWith("/")) {
            sanitized = sanitized.substring(1);
        }
        return sanitized.replace("..", "_");
    }

    private String resolveContainerMimeType() {
        if ("ASiC-E".equalsIgnoreCase(normalizeProperty(this.property))) {
            return ASICE_MIMETYPE_VALUE;
        }
        return ASICS_MIMETYPE_VALUE;
    }

    private byte[] buildPayloadDigestInput() {
        if (this.payloadEntries.size() == 1) {
            return this.payloadEntries.get(0).content;
        }

        StringBuilder builder = new StringBuilder();
        for (AsicPayloadEntry payloadEntry : this.payloadEntries) {
            builder.append(payloadEntry.entryName)
                    .append("|")
                    .append(payloadEntry.mimeType)
                    .append("|")
                    .append(Base64.getEncoder().encodeToString(payloadEntry.content))
                    .append("\n");
        }
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String resolvePayloadMimeType() {
        String mimeType = this.asicObject != null && this.asicObject.getAttributes() != null
                ? this.asicObject.getAttributes().get("payloadMimeType")
                : null;
        if (mimeType == null || mimeType.isBlank()) {
            return "application/octet-stream";
        }
        return mimeType;
    }

    private String normalizeProperty(String inputProperty) {
        if (inputProperty == null || inputProperty.isBlank()) {
            return DEFAULT_PROPERTY;
        }
        if ("ASIC-E".equalsIgnoreCase(inputProperty) || "ASiC-E".equalsIgnoreCase(inputProperty)) {
            return "ASiC-E";
        }
        return "ASiC-S";
    }

    private static class AsicPayloadEntry {
        private final String entryName;
        private final String mimeType;
        private final byte[] content;

        private AsicPayloadEntry(String entryName, String mimeType, byte[] content) {
            this.entryName = entryName;
            this.mimeType = mimeType;
            this.content = content;
        }
    }
}
