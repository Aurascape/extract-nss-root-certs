// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This utility parses Mozilla's certdata.txt and extracts a list of trusted
// certificates in PEM form.
//
// A current version of certdata.txt can be downloaded from:
//
//	https://raw.githubusercontent.com/mozilla-firefox/firefox/release/security/nss/lib/ckfw/builtins/certdata.txt
package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type Object struct {
	attrs        map[string]Attribute
	startingLine int // the line number that the object started on.
}

type Attribute struct {
	attrType string
	value    []byte
}

var (
	includeUntrusted   = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")
	toFiles            = flag.Bool("to-files", false, "If set, individual certificate files will be created in the current directory")
	ignoreListFilename = flag.String("ignore-list", "", "File containing a list of certificates to ignore")
)

func main() {
	flag.Parse()

	inFilename := "certdata.txt"
	if len(flag.Args()) == 1 {
		inFilename = flag.Arg(0)
	} else if len(flag.Args()) > 1 {
		fmt.Printf("Usage: %s [<certdata.txt file>]\n", os.Args[0])
		os.Exit(1)
	}

	ignoreList := make(map[string]string)
	if *ignoreListFilename != "" {
		ignoreListFile, err := os.Open(*ignoreListFilename)
		if err != nil {
			log.Fatalf("Failed to open ignore-list file: %s", err)
		}
		ignoreList = parseIgnoreList(ignoreListFile)
		ignoreListFile.Close()
	}

	inFile, err := os.Open(inFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	license, cvsId, objects := parseInput(inFile)
	inFile.Close()

	if !*toFiles {
		os.Stdout.WriteString(license)
		if len(cvsId) > 0 {
			os.Stdout.WriteString("CVS_ID " + cvsId + "\n")
		}
	}

	outputTrustedCerts(os.Stdout, objects, ignoreList)
}

// lineReader returns successive lines from an input file and keeps count of
// the current line number. It aborts the program on I/O errors or
// over-long lines.
type lineReader struct {
	scanner *bufio.Scanner
	lineNo  int
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{scanner: bufio.NewScanner(r)}
}

// next returns the next line of input. It returns ok == false at the end of
// the input.
func (lr *lineReader) next() (line string, ok bool) {
	if !lr.scanner.Scan() {
		if err := lr.scanner.Err(); err != nil {
			log.Fatalf("I/O error while reading input: %s", err)
		}
		return "", false
	}
	lr.lineNo++
	return lr.scanner.Text(), true
}

// parseIgnoreList parses the ignore-list file, which maps CKA_LABEL values
// (from the upstream roots file) to an optional comment which is displayed
// when skipping matching certificates.
func parseIgnoreList(r io.Reader) map[string]string {
	ignoreList := make(map[string]string)
	in := newLineReader(r)

	for {
		line, ok := in.next()
		if !ok {
			return ignoreList
		}
		if label, comment, found := strings.Cut(line, "#"); found {
			// This line has an additional comment.
			ignoreList[strings.TrimSpace(label)] = strings.TrimSpace(comment)
		} else {
			ignoreList[line] = ""
		}
	}
}

// parseInput parses a certdata.txt file into its license blob, the CVS id (if
// included) and a set of Objects.
func parseInput(inFile io.Reader) (license, cvsId string, objects []*Object) {
	in := newLineReader(inFile)

	// Discard anything prior to the license block.
	for {
		line, ok := in.next()
		if !ok {
			log.Fatalf("Read whole input and failed to find beginning of license")
		}
		if strings.Contains(line, "This Source Code") {
			license += line + "\n"
			break
		}
	}
	// Now collect the license block.
	// certdata.txt from hg.mozilla.org no longer contains CVS_ID.
	for {
		line, ok := in.next()
		if !ok || strings.Contains(line, "CVS_ID") || len(line) == 0 {
			break
		}
		license += line + "\n"
	}

	var currentObject *Object
	var beginData bool

	for {
		line, ok := in.next()
		if !ok {
			break
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if value, found := strings.CutPrefix(line, "CVS_ID "); found {
			cvsId = value
			continue
		}
		if line == "BEGINDATA" {
			beginData = true
			continue
		}

		words := strings.Fields(line)
		var value []byte
		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			startingLine := in.lineNo
			var ok bool
			value, ok = readMultilineOctal(in)
			if !ok {
				log.Fatalf("Failed to read octal value starting at line %d", startingLine)
			}
		} else if len(words) < 3 {
			log.Fatalf("Expected three or more values on line %d, but found %d", in.lineNo, len(words))
		} else {
			value = []byte(strings.Join(words[2:], " "))
		}

		if words[0] == "CKA_CLASS" {
			// Start of a new object.
			if currentObject != nil {
				objects = append(objects, currentObject)
			}
			currentObject = &Object{
				attrs:        make(map[string]Attribute),
				startingLine: in.lineNo,
			}
		}
		if currentObject == nil {
			log.Fatalf("Found attribute on line %d which appears to be outside of an object", in.lineNo)
		}
		currentObject.attrs[words[0]] = Attribute{
			attrType: words[1],
			value:    value,
		}
	}

	if !beginData {
		log.Fatalf("Read whole input and failed to find BEGINDATA")
	}

	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return license, cvsId, objects
}

// outputTrustedCerts writes a series of PEM encoded certificates to out by
// finding certificates and their trust records in objects.
func outputTrustedCerts(out io.Writer, objects []*Object, ignoreList map[string]string) {
	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")
	filenames := make(map[string]bool)

	for _, cert := range certs {
		derBytes := cert.attrs["CKA_VALUE"].value
		digest := sha1.Sum(derBytes)

		label := string(cert.attrs["CKA_LABEL"].value)
		if comment, present := ignoreList[strings.Trim(label, "\"")]; present {
			var sep string
			if len(comment) > 0 {
				sep = ": "
			}
			log.Printf("Skipping explicitly ignored certificate: %s%s%s", label, sep, comment)
			continue
		}

		parsed, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			log.Printf("Failed to parse certificate starting on line %d: %s", cert.startingLine, err)
			continue
		}

		var trust *Object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest[:], possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		if trust == nil {
			log.Fatalf("No trust found for certificate object starting on line %d (sha1: %x)", cert.startingLine, digest)
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value
		if len(trustType) == 0 {
			log.Fatalf("No CKA_TRUST_SERVER_AUTH found in trust starting at line %d", trust.startingLine)
		}

		var trusted bool
		switch string(trustType) {
		case "CKT_NSS_NOT_TRUSTED":
			// An explicitly distrusted cert
			trusted = false
		case "CKT_NSS_TRUSTED_DELEGATOR":
			// A cert trusted for issuing SSL server certs.
			trusted = true
		case "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_MUST_VERIFY_TRUST":
			// A cert not trusted for issuing SSL server certs, but is trusted for other purposes.
			trusted = false
		default:
			log.Fatalf("Unknown trust value '%s' found for trust record starting on line %d", trustType, trust.startingLine)
		}

		if !trusted && !*includeUntrusted {
			continue
		}

		block := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}

		if *toFiles {
			label = strings.TrimPrefix(label, "\"")
			label = strings.TrimSuffix(label, "\"")
			// The label may contain hex-escaped, UTF-8 characters.
			label = unescapeLabel(label)
			label = strings.ReplaceAll(label, " ", "_")
			label = strings.ReplaceAll(label, "/", "_")

			filename := label
			for i := 2; filenames[filename]; i++ {
				filename = label + "-" + strconv.Itoa(i)
			}
			filenames[filename] = true

			file, err := os.Create(filename + ".pem")
			if err != nil {
				log.Fatalf("Failed to create output file: %s\n", err)
			}
			pem.Encode(file, block)
			file.Close()
			fmt.Fprintf(out, "%s.pem\n", filename)
			continue
		}

		fmt.Fprintf(out, "\n")
		if !trusted {
			fmt.Fprintf(out, "# NOT TRUSTED FOR SSL\n")
		}

		fmt.Fprintf(out, "# Issuer: %s\n", nameToString(parsed.Issuer))
		fmt.Fprintf(out, "# Subject: %s\n", nameToString(parsed.Subject))
		fmt.Fprintf(out, "# Label: %s\n", label)
		fmt.Fprintf(out, "# Serial: %s\n", parsed.SerialNumber)
		if t, ok := distrustAfter(cert, "CKA_NSS_SERVER_DISTRUST_AFTER"); ok {
			fmt.Fprintf(out, "# Server Distrust After: %s\n", t.Format(time.RFC3339))
			fmt.Fprintf(out, "#   (Mozilla rejects server certificates issued by this root after that\n")
			fmt.Fprintf(out, "#   date. This cannot be expressed in a PEM bundle.)\n")
		}
		if t, ok := distrustAfter(cert, "CKA_NSS_EMAIL_DISTRUST_AFTER"); ok {
			fmt.Fprintf(out, "# Email Distrust After: %s\n", t.Format(time.RFC3339))
		}
		md5Digest := md5.Sum(parsed.Raw)
		sha1Digest := sha1.Sum(parsed.Raw)
		sha256Digest := sha256.Sum256(parsed.Raw)
		fmt.Fprintf(out, "# MD5 Fingerprint: %s\n", fingerprintString(md5Digest[:]))
		fmt.Fprintf(out, "# SHA1 Fingerprint: %s\n", fingerprintString(sha1Digest[:]))
		fmt.Fprintf(out, "# SHA256 Fingerprint: %s\n", fingerprintString(sha256Digest[:]))
		pem.Encode(out, block)
	}
}

// distrustAfter returns the time contained in a CKA_NSS_SERVER_DISTRUST_AFTER
// or CKA_NSS_EMAIL_DISTRUST_AFTER attribute of cert.
func distrustAfter(cert *Object, attrName string) (time.Time, bool) {
	attr, present := cert.attrs[attrName]
	if !present || attr.attrType != "MULTILINE_OCTAL" {
		return time.Time{}, false
	}
	// The value is an ASN.1 UTCTime string such as "241130235959Z".
	t, err := time.Parse("060102150405Z0700", string(attr.value))
	if err != nil {
		log.Fatalf("Failed to parse %s value %q starting on line %d: %s", attrName, attr.value, cert.startingLine, err)
	}
	return t, true
}

// nameToString converts name into a string representation containing the
// CommonName, Organization and OrganizationalUnit.
func nameToString(name pkix.Name) string {
	ret := ""
	if len(name.CommonName) > 0 {
		ret += "CN=" + name.CommonName
	}

	if org := strings.Join(name.Organization, "/"); len(org) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "O=" + org
	}

	if orgUnit := strings.Join(name.OrganizationalUnit, "/"); len(orgUnit) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "OU=" + orgUnit
	}

	return ret
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*Object, class string) (out []*Object) {
	for _, object := range in {
		if string(object.attrs["CKA_CLASS"].value) == class {
			out = append(out, object)
		}
	}
	return
}

// readMultilineOctal converts a series of lines of octal values into a slice
// of bytes.
func readMultilineOctal(in *lineReader) ([]byte, bool) {
	var value []byte

	for {
		line, ok := in.next()
		if !ok {
			// Missing "END".
			return nil, false
		}
		if line == "END" {
			return value, true
		}

		for _, octalStr := range strings.Split(line, "\\") {
			if len(octalStr) == 0 {
				continue
			}
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				log.Printf("error converting octal string '%s' on line %d", octalStr, in.lineNo)
				return nil, false
			}
			value = append(value, byte(v))
		}
	}
}

// fingerprintString returns a colon-separated, lowercase hex encoding of
// digest.
func fingerprintString(digest []byte) string {
	hexDigits := make([]string, len(digest))
	for i, b := range digest {
		hexDigits[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(hexDigits, ":")
}

func isHex(c rune) (value byte, ok bool) {
	switch {
	case c >= '0' && c <= '9':
		return byte(c) - '0', true
	case c >= 'a' && c <= 'f':
		return byte(c) - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return byte(c) - 'A' + 10, true
	}

	return 0, false
}

// unescapeLabel unescapes "\xab" style hex-escapes.
func unescapeLabel(escaped string) string {
	var out []byte
	var last rune
	var value byte
	state := 0

	for _, r := range escaped {
		switch state {
		case 0:
			if r == '\\' {
				state++
				continue
			}
		case 1:
			if r == 'x' {
				state++
				continue
			}
			out = append(out, '\\')
		case 2:
			if v, ok := isHex(r); ok {
				value = v
				last = r
				state++
				continue
			} else {
				out = append(out, '\\', 'x')
			}
		case 3:
			if v, ok := isHex(r); ok {
				value <<= 4
				value += v
				out = append(out, value)
				state = 0
				continue
			} else {
				out = append(out, '\\', 'x')
				out = utf8.AppendRune(out, last)
			}
		}
		state = 0
		out = utf8.AppendRune(out, r)
	}

	switch state {
	case 3:
		out = append(out, '\\', 'x')
		out = utf8.AppendRune(out, last)
	case 2:
		out = append(out, '\\', 'x')
	case 1:
		out = append(out, '\\')
	}

	return string(out)
}
