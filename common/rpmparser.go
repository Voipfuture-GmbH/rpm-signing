package common

import (
	"bytes"
	"cmp"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

// RESERVED_SPACE_ALLOCATION_SIZE is the size in bytes
// that any newly created (or resized) SigTagReservedSpace index entry
// will get
const RESERVED_SPACE_ALLOCATION_SIZE = uint32(4096)

type SignatureVersion struct {
	Id    uint8
	Label string
}

func (v SignatureVersion) String() string {
	return v.Label
}

type RpmFileFormatVersion struct {
	Major uint8
	Minor uint8
}

func (v RpmFileFormatVersion) CompareTo(other RpmFileFormatVersion) int {
	r := int(v.Major) - int(other.Major)
	if r == 0 {
		r = int(v.Minor) - int(other.Minor)
	}
	return r
}

func (v RpmFileFormatVersion) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

var (
	SIGNATURE_VERSION_V3 SignatureVersion = SignatureVersion{Id: 3, Label: "V3"}
	SIGNATURE_VERSION_V4 SignatureVersion = SignatureVersion{Id: 4, Label: "V4"}
	SIGNATURE_VERSION_V6 SignatureVersion = SignatureVersion{Id: 6, Label: "V6"}
)

func AllSignatureVersions() []SignatureVersion {
	return []SignatureVersion{
		SIGNATURE_VERSION_V3,
		SIGNATURE_VERSION_V4,
		SIGNATURE_VERSION_V6,
	}
}

type PackageType uint16

const (
	PACKAGE_TYPE_BINARY PackageType = 0x00
	PACKAGE_TYPE_SOURCE PackageType = 0x01
)

type FormatType uint32

const (
	FORMAT_TYPE_NULL              FormatType = 0x00
	FORMAT_TYPE_CHAR              FormatType = 0x01
	FORMAT_TYPE_INT8              FormatType = 0x02
	FORMAT_TYPE_INT16             FormatType = 0x03
	FORMAT_TYPE_INT32             FormatType = 0x04
	FORMAT_TYPE_INT64             FormatType = 0x05
	FORMAT_TYPE_STRING            FormatType = 0x06
	FORMAT_TYPE_BINARY            FormatType = 0x07
	FORMAT_TYPE_STRING_ARRAY      FormatType = 0x08
	FORMAT_TYPE_I18N_STRING_ARRAY FormatType = 0x09
)

/*
Data Type Name,Type Value,Data Type Size,Alignment Requirement,Notes
RPM_CHAR_TYPE,1,1 byte,1-byte (Unaligned),Byte values
RPM_INT8_TYPE,2,1 byte,1-byte (Unaligned),8-bit integers
RPM_INT16_TYPE,3,2 bytes,2-byte boundary,Offset pos % 2 == 0
RPM_INT32_TYPE,4,4 bytes,4-byte boundary,Offset pos % 4 == 0
RPM_INT64_TYPE,5,8 bytes,8-byte boundary,Offset pos % 8 == 0
RPM_STRING_TYPE,6,Variable,1-byte (Unaligned),Null-terminated string (\0)
RPM_BIN_TYPE,7,1 byte,1-byte (Unaligned),Raw byte array/blob
RPM_STRING_ARRAY_TYPE,8,Variable,1-byte (Unaligned),Sequence of null-terminated strings
RPM_I18NSTRING_TYPE,9,Variable,1-byte (Unaligned),Same encoding layout as string arrays
*/
func (f FormatType) GetRequiredAlignment() uint8 {
	switch f {
	case FORMAT_TYPE_CHAR:
		return 1
	case FORMAT_TYPE_INT8:
		return 1
	case FORMAT_TYPE_INT16:
		return 2
	case FORMAT_TYPE_INT32:
		return 4
	case FORMAT_TYPE_INT64:
		return 8
	case FORMAT_TYPE_STRING:
		return 1
	case FORMAT_TYPE_BINARY:
		return 1
	case FORMAT_TYPE_STRING_ARRAY:
		return 1
	case FORMAT_TYPE_I18N_STRING_ARRAY:
		return 1
	default:
		panic(fmt.Sprintf("Unhandled format type %d", f))
	}
}

var formatStrings = []string{
	"null",
	"char",
	"int8",
	"int16",
	"int32",
	"int64",
	"string",
	"binary",
	"string-array",
	"i18n-string-array",
}

func (f FormatType) GetFormatTypeLabel() string {
	if int(f) >= len(formatStrings) {
		return fmt.Sprintf("format-type:%d", f)
	}
	return formatStrings[int(f)]
}

/*
The Index Entry

The header structure's index is made up of zero or more index entries.
Each entry is sixteen bytes long.
The first four bytes contain a tag — a numeric value that identifies what type of data is pointed to by the entry.
The tag values change according to the header structure's position in the RPM file.
A list of the actual tag values, and what they represent, will be included later in this appendix.

Following the tag, is a four-byte type, which is a numeric value that describes the format of the data pointed to by the entry.
The types and their values do not change from header structure to header structure. Here is the current list:

	NULL = 0
	CHAR = 1
	INT8 = 2
	INT16 = 3
	INT32 = 4
	INT64 = 5
	STRING = 6
	BIN = 7
	STRING_ARRAY = 8

A few of the data types might need some clarification. The STRING data type is simply a null-terminated string, while
the STRING_ARRAY is a collection of strings. Finally, the BIN data type is a collection of binary data.
This is normally used to identify data that is longer than an INT, but not a printable STRING.

Next is a four-byte offset that contains the position of the data, relative to the beginning of the store.

Finally, there is a four-byte count that contains the number of data items pointed to by the index entry.
There are a few wrinkles to the meaning of the count, and they center around the STRING and STRING_ARRAY data types.
STRING data always has a count of 1, while STRING_ARRAY data has a count equal to the number of strings contained in the store.
*/
type IndexEntry struct {
	isMainHeaderEntry bool // internal-use only, not stored in RPM file
	// data from index entry
	tag         uint32 // The first four bytes contain a tag — a numeric value that identifies what type of data is pointed to by the entry.
	formatType  uint32 // Following the tag, is a four-byte type, which is a numeric value that describes the format of the data pointed to by the entry.
	offset      uint32 // Next is a four-byte offset that contains the position of the data, relative to the beginning of the store.
	dataItemCnt uint32 // STRING data always has a count of 1, while STRING_ARRAY data has a count equal to the number of strings contained in the store.
	// data of this index entry from the "data store"
	payload []byte
}

func (i *IndexEntry) endOffset() uint32 {
	return i.offset + uint32(len(i.payload))
}

func (i *IndexEntry) Int32Value() int32 {
	if FormatType(i.formatType) != FORMAT_TYPE_INT32 {
		panic(fmt.Sprintf("Int32Value() called on IndexEntry of type %d , expected type %d", i.formatType, FORMAT_TYPE_INT32))
	}
	s := NewSerializerFromArray(i.payload)
	value, err := s.readWord()
	if err != nil {
		panic("Failed to read int32 from " + i.RawString())
	}
	return int32(value)
}

func (i *IndexEntry) StringValue() string {
	if FormatType(i.formatType) != FORMAT_TYPE_STRING {
		panic(fmt.Sprintf("StringValue() called on IndexEntry of type %d , expected type %d", i.formatType, FORMAT_TYPE_STRING))
	}
	value := parseNullTerminatedStrings(i.payload)
	if len(value) != 1 {
		panic("StringValue() found more than one string?")
	}
	return value[0]
}

func (i *IndexEntry) Tag() TagValue {
	if i.isMainHeaderEntry {
		return LookupMainTag(i.tag)
	}
	return LookupSignatureTag(i.tag)
}

func (i *IndexEntry) PayloadAsPrettyString() string {

	switch FormatType(i.formatType) {
	case FORMAT_TYPE_NULL:
		values := make([]string, 0, i.dataItemCnt)
		for cnt := i.dataItemCnt; cnt > 0; cnt-- {
			values = append(values, "<NULL>")
		}
		return strings.Join(values, ", ")
	case FORMAT_TYPE_CHAR:
		var values strings.Builder
		for _, value := range i.payload {
			values.WriteString(string(value))
		}
		return values.String()
	case FORMAT_TYPE_INT8:
		values := make([]string, 0, i.dataItemCnt)
		for _, value := range i.payload {
			values = append(values, fmt.Sprintf("%d", int8(value)))
		}
		return strings.Join(values, ", ")
	case FORMAT_TYPE_INT16:
		s := NewSerializerFromArray(i.payload)
		values := make([]string, 0, i.dataItemCnt)
		for cnt := i.dataItemCnt; cnt > 0; cnt-- {
			if result, err := s.readShort(); err == nil {
				values = append(values, fmt.Sprintf("%d", int16(result)))
			} else {
				msg := fmt.Sprintf("Payload too short on %s", i.RawString())
				panic(msg)
			}
		}
		return strings.Join(values, ", ")
	case FORMAT_TYPE_INT32:
		s := NewSerializerFromArray(i.payload)
		values := make([]string, 0, i.dataItemCnt)
		for cnt := i.dataItemCnt; cnt > 0; cnt-- {
			if result, err := s.readWord(); err == nil {
				values = append(values, fmt.Sprintf("%d", int32(result)))
			} else {
				msg := fmt.Sprintf("Payload too short on %s", i.RawString())
				panic(msg)
			}
		}
		return strings.Join(values, ", ")
	case FORMAT_TYPE_INT64:
		s := NewSerializerFromArray(i.payload)
		values := make([]string, 0, i.dataItemCnt)
		for cnt := i.dataItemCnt; cnt > 0; cnt-- {
			if result, err := s.readLongWord(); err == nil {
				values = append(values, fmt.Sprintf("%d", int64(result)))
			} else {
				msg := fmt.Sprintf("Payload too short on %s", i.RawString())
				panic(msg)
			}
		}
		return strings.Join(values, ", ")
	case FORMAT_TYPE_BINARY:
		return hex.Dump(i.payload)
	case FORMAT_TYPE_STRING, FORMAT_TYPE_STRING_ARRAY, FORMAT_TYPE_I18N_STRING_ARRAY:
		terminatedStrings := parseNullTerminatedStrings(i.payload)
		if len(terminatedStrings) != int(i.dataItemCnt) {
			fmt.Printf("PAYLOAD: len %d, %s\n", len(i.payload), hex.Dump(i.payload))
			panic(fmt.Sprintf("String payload count mismatch on %s. Expected %d strings but only got %d",
				i.RawString(), i.dataItemCnt, len(terminatedStrings)))
		}
		return strings.Join(terminatedStrings, ", ")
	default:
		panic(fmt.Sprintf("Unknown format type %d (0x%x) on index entry", i.formatType, i.formatType))
	}
}

func (i *IndexEntry) PrettyString() string {
	return fmt.Sprintf("%s(%d) = %s", i.Tag().Label(), i.Tag().ID(), i.PayloadAsPrettyString())
}

func (i *IndexEntry) RawString() string {
	if i == nil {
		return "<nil>"
	}

	return fmt.Sprintf("IndexEntry{%s, tag: %d, format: %d, offset: %d, dataItemCnt: %d, payloadLen: %d (0x%x)}",
		i.Tag().Label(), i.tag, i.formatType, i.offset, i.dataItemCnt, len(i.payload), len(i.payload))
}

func (i *IndexEntry) String() string {
	if i == nil {
		return "<nil>"
	}

	formatName := (FormatType)(i.formatType).GetFormatTypeLabel()

	return fmt.Sprintf("IndexEntry{%s, tag: %d, %s, offset: %d, dataItemCnt: %d, payloadLen: %d (0x%x), value: %s}",
		i.Tag().Label(), i.tag, formatName, i.offset, i.dataItemCnt, len(i.payload), len(i.payload), i.PayloadAsPrettyString())
}

func (i *IndexEntry) populatePayload(s Serializer) error {
	var err error
	// fmt.Printf("Populating payload for IndexEntry %s starting at serializer offset 0x%x\n", i.String(), s.offset())
	switch i.formatType {
	case 0: // NULL = 0
		return nil
	case 1: // CHAR = 1
		if i.payload, err = s.readByteArray(1); err != nil {
			return err
		}
		break
	case 2: // INT8 = 2
		if i.payload, err = s.readByteArray(i.dataItemCnt); err != nil {
			return err
		}
		break
	case 3: // INT16 = 3
		if i.payload, err = s.readByteArray(i.dataItemCnt * 2); err != nil {
			return err
		}
		break
	case 4: // INT32 = 4
		if i.payload, err = s.readByteArray(i.dataItemCnt * 4); err != nil {
			return err
		}
		break
	case 5: // INT64 = 5
		if i.payload, err = s.readByteArray(i.dataItemCnt * 8); err != nil {
			return err
		}
		break
	case 6: // STRING = 6
		i.payload, err = s.readNullTerminatedString()
		if len(i.payload) == 0 {
			return fmt.Errorf("payload too short on %s", i.RawString())
		}
		if err != nil {
			return err
		}
		break
	case 7: // BIN = 7
		if i.payload, err = s.readByteArray(i.dataItemCnt); err != nil {
			return err
		}
		break
	case 8, 9: // STRING_ARRAY = 8 | FORMAT_TYPE_I18N_STRING_ARRAY = 9
		for idx := uint32(0); idx < i.dataItemCnt; idx++ {
			s, err := s.readNullTerminatedString()
			if err != nil {
				return err
			}
			i.payload = append(i.payload, s...)
		}
		break
	default:
		return errors.New("invalid index entry")
	}
	return nil
}

type RpmLead struct {
	Magic         [4]uint8
	Major         uint8
	Minor         uint8
	packageType   uint16
	ArchNum       uint16
	name          [66]uint8
	OsNum         uint16
	SignatureType uint16
	Reserved      [16]uint8
}

var leadMagic = [4]byte{0xed, 0xab, 0xee, 0xdb}
var headerMagic = [3]byte{0x8e, 0xad, 0xe8}

type RpmHeader struct {

	/*
		     * The header structure header always starts with a three-byte Magic number: 8e ad e8.
			 *
		     * - Following this is a one-byte version number.
		     * - Next are four bytes that are reserved for future expansion.
		     * - After the reserved bytes, there is a four-byte number that indicates how many index entries exist in this header structure
		     * - followed by another four-byte number indicating how many bytes of data are part of the header structure.
	*/
	Magic            [3]uint8
	version          uint8
	reserved         [4]uint8
	indexEntryCount  uint32
	storeSizeInBytes uint32

	/*
	 * ------------- internal metadata ---------------
	 */

	IsMainHeader bool
	IndexEntries []IndexEntry
	// absolute start offset of header structure in input
	headerStartOffset uint64
	// absolute start offset of this header's index entries in input
	IndicesStartOffset uint64
	// absolute start offset of this header's data store in input
	DataStoreStartOffset uint64
	SignedRegion         *SignedRegion

	// Digest values
	//
	// CAREFUL: These fields ONLY get calculated for the main header structure,
	//          NOT the signature header structure

	// MD5 hash over main header AND CPIO payload
	Md5Digest hash.Hash
	// SHA1 digest over main header only
	Sha1Digest hash.Hash
	// SHA256 digest over main header only
	Sha256Digest hash.Hash
}

type SignedRegion struct {
	// start offset of table with signed index entries
	IndexEntriesStartOffset uint64
	// number of signed index entries
	IndexEntryCount uint32
	// total size (in bytes) of index entries + associated data store bytes
	Length uint64
}

func (r SignedRegion) String() string {
	return fmt.Sprintf("Signed region{offset: %d (0x%x), length: %d (0x%x), indexEntryCnt: %d (%x)",
		r.IndexEntriesStartOffset, r.IndexEntriesStartOffset, r.Length, r.Length, r.IndexEntryCount, r.IndexEntryCount)
}

type RpmFile struct {
	Lead                  RpmLead
	SignatureHeader       RpmHeader
	MainHeader            RpmHeader
	PayloadStartOffset    uint64
	CompressedPayloadSize uint64
}

func (header *RpmHeader) DumpIndexEntries(truncateValuesToLength int, printCompact bool) string {

	rows := make([][]string, 0)

	uint32ToString := func(i uint32) string {
		return strconv.FormatUint(uint64(i), 10)
	}

	// calculate data for each table row
	columnNames := []string{"Tag", "Tag ID", "Format", "Item Count", "Start adr", "End adr", "Length", "Payload"}

	for _, entry := range header.IndexEntries {
		row := make([]string, 0)
		row = append(row, entry.Tag().Label())                                     // tag label
		row = append(row, uint32ToString(entry.Tag().ID()))                        // tag ID
		row = append(row, FormatType(entry.formatType).GetFormatTypeLabel())       // format type label
		row = append(row, uint32ToString(entry.dataItemCnt))                       // data item count
		row = append(row, uint32ToString(entry.offset))                            // payload start offset
		row = append(row, uint32ToString(entry.offset+uint32(len(entry.payload)))) // payload end offset
		row = append(row, strconv.Itoa(len(entry.payload)))                        // payload length
		valueString := entry.PayloadAsPrettyString()
		if len(valueString) > truncateValuesToLength {
			valueString = valueString[0:truncateValuesToLength] + "..."
		}
		row = append(row, valueString) // payload value
		rows = append(rows, row)
	}

	// find max. width of each column
	var columnCount int
	if len(rows) > 0 {
		columnCount = len(rows[0])
	} else {
		columnCount = 0
	}
	maxColumnWidths := make([]int, columnCount)

	updateMaxWidths := func(row []string) {
		for colIdx, cellContent := range row {
			if len(cellContent) > maxColumnWidths[colIdx] {
				maxColumnWidths[colIdx] = len(cellContent)
			}
		}
	}

	updateMaxWidths(columnNames)
	for _, row := range rows {
		updateMaxWidths(row)
	}

	// apply padding
	var separatorCols []string
	for colIdx := range columnNames {
		separatorCols = append(separatorCols, strings.Repeat(" ", maxColumnWidths[colIdx]))
		columnNames[colIdx] = CenterPad(columnNames[colIdx], " ", maxColumnWidths[colIdx])
	}

	// assemble table
	separatorLine := func(prefix string, padChar string, joinChar string, suffix string) string {
		var result strings.Builder
		for idx := 0; idx < len(columnNames); idx++ {
			result.WriteString(strings.Repeat(padChar, maxColumnWidths[idx]))
			if (idx + 1) < len(columnNames) {
				result.WriteString(joinChar)
			}
		}
		return prefix + result.String() + suffix
	}

	var result strings.Builder
	result.WriteString(separatorLine("|", "-", "|", "|") + "\n")

	applyPadding := func(row []string) {
		for colIdx := 0; colIdx < columnCount; colIdx++ {
			padLen := maxColumnWidths[colIdx]
			if colIdx == 0 {
				row[colIdx] = RightPad(row[colIdx], " ", padLen)
			} else {
				row[colIdx] = CenterPad(row[colIdx], " ", padLen)
			}
		}
	}

	applyPadding(columnNames)
	result.WriteString("|" + strings.Join(columnNames, "|") + "|\n")
	result.WriteString(separatorLine("|", "-", "|", "|"))
	if len(rows) > 0 {
		result.WriteString("\n")
	}

	for idx, row := range rows {
		applyPadding(row)
		result.WriteString("|" + strings.Join(row, "|") + "|")
		if !printCompact {
			result.WriteString("\n")
			result.WriteString(separatorLine("+", "-", "+", "+"))
		}

		if (idx + 1) < len(rows) {
			result.WriteString("\n")
		}
	}
	return result.String()
}

func (header *RpmHeader) DeleteIndexEntryIfExists(tag TagValue) {
	existing := header.FindIndexEntry(tag)
	if existing != nil {
		header.DeleteIndexEntry(*existing)
	}
}

func (header *RpmHeader) DeleteIndexEntry(entry IndexEntry) {
	for idx, e := range header.IndexEntries {
		if e.tag == entry.tag {
			header.IndexEntries = RemoveAtIndex(header.IndexEntries, idx)
			header.indexEntryCount--
			header.updateSignedRegionTrailer()
			// the removed entry leaves a hole in the data store, close it again
			header.syncDataStoreLayout()
			return
		}
	}
}

// FindNextSuitablePayloadOffset returns a properly an offset
// , properly aligned according to the given FormatType's requirements, AT THE VERY END of the datastore.

func (header *RpmHeader) FindNextSuitablePayloadOffset(format FormatType) uint32 {

	// >>> Do not change allocation semantics, calling code relies on the fact
	// that the returned offset is at the very end of the data store <<<
	trailer := header.regionTrailerEntry()
	var entryWithLargestOffset *IndexEntry
	for idx := range header.IndexEntries {
		e := &header.IndexEntries[idx]
		if e == trailer {
			// the region trailer is kept at the end of the data store by
			// syncDataStoreLayout(), allocating behind it would bury it
			continue
		}
		if entryWithLargestOffset == nil || e.offset > entryWithLargestOffset.offset {
			entryWithLargestOffset = e
		}
	}
	payloadOffset := uint32(0)
	if entryWithLargestOffset != nil {
		payloadOffset = entryWithLargestOffset.offset + uint32(len(entryWithLargestOffset.payload))
		alignmentOffset := CalcAlignmentByteCount(uint64(payloadOffset), format.GetRequiredAlignment())
		payloadOffset += uint32(alignmentOffset)
	}
	return payloadOffset
}

// allocateSpaceInDatastore allocates a specific amount of space in the datastore
// that satisfies alignment requirements for the given FormatType and
// at the same time tries to minimize both the size change and
// changes to the datastore contents.
// Returns the allocated address within the header's data store
func (header *RpmHeader) allocateSpaceInDatastore(requestedSize uint32, format FormatType) uint32 {
	reservedSpace := header.FindIndexEntry(SigTagReservedSpace)

	RootLogger().Debugf("Trying to allocate %d bytes for payload of type %s", requestedSize, format.GetFormatTypeLabel())

	if reservedSpace != nil {
		// data store already has a "reserved space" entry

		reservedSpaceAtEndOfDataStore := header.isAtEndOfDataStore(*reservedSpace)

		RootLogger().Debugf("Found %d bytes of reserved space (at end of data store: %v) ", reservedSpace.dataItemCnt, reservedSpaceAtEndOfDataStore)

		allocatedAddress := reservedSpace.offset
		// calculate necessary alignment assuming we'd use that address
		alignment := uint32(CalcAlignmentByteCount(uint64(allocatedAddress), format.GetRequiredAlignment()))
		allocatedAddress += alignment
		// actual size requirements to compare against size of reserved space
		actualSize := requestedSize + alignment
		remainingReservedSpace := int(reservedSpace.dataItemCnt) - int(actualSize)

		if remainingReservedSpace > 0 {
			// reserved space is large enough to hold the payload,
			// just shift it by the actual size needed to store
			// the payload
			RootLogger().Debugf("Reserved space can accommodate payload of size %d", actualSize)
			reservedSpace.offset += actualSize
			reservedSpace.dataItemCnt = uint32(remainingReservedSpace)
			reservedSpace.payload = make([]byte, remainingReservedSpace)

			return allocatedAddress
		}
		if remainingReservedSpace == 0 {

			RootLogger().Debug("Reserved space completely used up")

			// reserved space completely used up, move after allocation
			remainingReservedSpace = int(RESERVED_SPACE_ALLOCATION_SIZE)

			reservedSpace.offset += actualSize
			reservedSpace.dataItemCnt = uint32(remainingReservedSpace)
			reservedSpace.payload = make([]byte, remainingReservedSpace)

			return allocatedAddress
		}

		// reserved space is too small to hold the payload

		RootLogger().Debug("Reserved space is too small")

		remainingReservedSpace = int(actualSize) + int(RESERVED_SPACE_ALLOCATION_SIZE)

		reservedSpace.dataItemCnt = uint32(remainingReservedSpace)
		reservedSpace.payload = make([]byte, remainingReservedSpace)

		if reservedSpaceAtEndOfDataStore {
			RootLogger().Debug("Reserved space grown to new size")
			// -> ok to just grow the reserved space and recurse
			return header.allocateSpaceInDatastore(requestedSize, format)
		}

		RootLogger().Debug("Reserved space too small but cannot be grown (not at end of data store)")

		// reserved space is too small, but we cannot grow it
		// as it's not at the end of the data store
		// -> move it to the very end, leaving behind
		// a "gap" within the data store
		reservedSpace.offset = header.FindNextSuitablePayloadOffset(FORMAT_TYPE_BINARY)

		return header.allocateSpaceInDatastore(requestedSize, format)
	}

	// no reserved space, add one that's large enough to hold
	// the payload at the very end of the data store
	reservedSpaceStart := header.FindNextSuitablePayloadOffset(FORMAT_TYPE_BINARY)

	payloadAlignment := uint32(CalcAlignmentByteCount(uint64(reservedSpaceStart), format.GetRequiredAlignment()))

	// make sure recursive allocation will succeed on
	// the next turn
	reservedSize := RESERVED_SPACE_ALLOCATION_SIZE + requestedSize + payloadAlignment

	RootLogger().Debugf("Found no index entry for reserved space, creating a new one at offset 0x%x with size %d bytes", reservedSpaceStart, reservedSize)

	reservedSpace = &IndexEntry{
		isMainHeaderEntry: header.IsMainHeader,
		tag:               SigTagReservedSpace.ID(),
		formatType:        uint32(FORMAT_TYPE_BINARY),
		offset:            reservedSpaceStart,
		dataItemCnt:       reservedSize,
		payload:           make([]byte, reservedSize),
	}
	// inserted directly: addIndexEntry() would call back into this method to find an
	// offset, and as there still would be no reserved space to allocate from at that
	// point it would recurse indefinitely
	header.insertIndexEntry(*reservedSpace)
	return header.allocateSpaceInDatastore(requestedSize, format)
}

func (header *RpmHeader) addIndexEntry(newEntry IndexEntry) {

	if header.IsMainHeader != newEntry.isMainHeaderEntry {
		panic(fmt.Sprintf("IndexEntry IsMainHeader does not match with header : %v", newEntry))
	}

	newEntry.offset = header.allocateSpaceInDatastore(uint32(len(newEntry.payload)), FormatType(newEntry.formatType))

	header.insertIndexEntry(newEntry)
}

// insertIndexEntry adds an index entry whose data store offset has already been
// determined and brings the header's derived fields back in sync. The entry is
// inserted so the index entries stay sorted by tag number, which is the order the
// RPM header format requires them in. Sorting by tag also keeps the region trailer
// in the first slot, as its tag is the lowest one a header can carry.
func (header *RpmHeader) insertIndexEntry(newEntry IndexEntry) {

	// CAREFUL: The following requirements are not mentioned anywhere in the RPM file format
	// "documentation" but enforced by the RPM tool code, causing errors when violated:
	//
	// - index entries need to be sorted ascending by tag number
	// - the order of payload entries in the datastore section needs to be
	//   in sync with the order of index entries within the index table

	insertAt := len(header.IndexEntries)
	for idx := range header.IndexEntries {
		if header.IndexEntries[idx].tag > newEntry.tag {
			insertAt = idx
			break
		}
	}
	header.IndexEntries = slices.Insert(header.IndexEntries, insertAt, newEntry)
	header.indexEntryCount++
	header.updateSignedRegionTrailer()
	// the entry was allocated space at the end of the data store while its index
	// entry went somewhere in the middle, so the data has to be laid out again
	header.syncDataStoreLayout()
}

// regionTrailerEntry returns this header's region trailer index entry, or nil if the
// header has none. The trailer is the one entry that does not follow index entry
// order: it stays the FIRST index entry while its 16 bytes of data occupy the very
// END of the data store, because rpm requires the region to span the whole store.
func (header *RpmHeader) regionTrailerEntry() *IndexEntry {

	if header.IsMainHeader {
		return header.FindIndexEntry(TagHeaderImmutable)
	}
	return header.FindIndexEntry(SigTagHeaderSignatures)
}

// syncDataStoreLayout re-assigns every index entry's data store offset so the data is
// laid out in index entry order, each entry aligned as its format type requires, and
// updates the store size to match. The region trailer is excluded and placed last.
//
// rpm walks the index entries in order and rejects a header as soon as an entry's
// data starts before the end of the previous entry's data ("Previous data must not
// overlap" in hdrblobVerifyInfo()), so index entry order and data store order have to
// stay in lock-step. Re-placing the data rather than re-sorting the index entries is
// what keeps them sorted by tag number, which is the order the header format documents.
//
// This is a no-op for a header that was parsed and not modified afterwards, as rpm
// packs the data store exactly the same way.
func (header *RpmHeader) syncDataStoreLayout() {

	trailer := header.regionTrailerEntry()

	nextOffset := uint32(0)
	place := func(entry *IndexEntry) {
		alignment := FormatType(entry.formatType).GetRequiredAlignment()
		nextOffset += uint32(CalcAlignmentByteCount(uint64(nextOffset), alignment))
		entry.offset = nextOffset
		nextOffset += uint32(len(entry.payload))
	}

	for idx := range header.IndexEntries {
		if entry := &header.IndexEntries[idx]; entry != trailer {
			place(entry)
		}
	}
	if trailer != nil {
		place(trailer)
	}
	header.storeSizeInBytes = nextOffset
}

// updateSignedRegionTrailer rewrites the signature header's HEADERSIGNATURES region
// trailer so it again covers every index entry. The trailer stores the start of the
// index entry table as a negative offset and counts itself, so that offset is
// -(16 * number of index entries). No-op for the main header, which has no such trailer.
func (header *RpmHeader) updateSignedRegionTrailer() {

	if header.IsMainHeader {
		return
	}
	trailer := header.FindIndexEntry(SigTagHeaderSignatures)
	if trailer == nil {
		// header was built from scratch rather than parsed, nothing to keep in sync
		return
	}
	if len(trailer.payload) != 16 {
		panic(fmt.Sprintf("HEADERSIGNATURES trailer has %d payload bytes, expected 16", len(trailer.payload)))
	}

	regionSize := uint32(16 * len(header.IndexEntries))
	negativeOffset := uint32(-int32(regionSize))

	// payload layout: tag (4) | format type (4) | negative offset (4) | byte count (4)
	trailer.payload[8] = byte(negativeOffset >> 24)
	trailer.payload[9] = byte(negativeOffset >> 16)
	trailer.payload[10] = byte(negativeOffset >> 8)
	trailer.payload[11] = byte(negativeOffset)

	if header.SignedRegion != nil {
		header.SignedRegion.IndexEntryCount = regionSize / 16
		header.SignedRegion.IndexEntriesStartOffset = header.DataStoreStartOffset - uint64(regionSize)
	}
}

func (header *RpmHeader) isAtEndOfDataStore(entry IndexEntry) bool {

	trailer := header.regionTrailerEntry()
	largestEndOffset := uint32(0)
	lastIdx := -1
	for idx := range header.IndexEntries {
		e := &header.IndexEntries[idx]
		if e == trailer {
			// the region trailer always ends the data store, it would hide
			// the last entry that can actually be grown in place
			continue
		}
		if e.endOffset() > largestEndOffset {
			largestEndOffset = e.endOffset()
			lastIdx = idx
		}
	}
	if lastIdx == -1 {
		panic("No index entries")
	}
	last := header.IndexEntries[lastIdx]
	// any header structure can have at most one
	// index entry for any given tag
	return last.tag == entry.tag
}

func (header *RpmHeader) SetOrAddIndexEntry(tag TagValue, format FormatType, newDataItemCnt uint32, newPayload []byte) {

	existing := header.FindIndexEntry(tag)
	if existing != nil {

		if FormatType(existing.formatType) != format {
			panic("Trying to replace entry with same tag but different format type?")
		}

		// CAREFUL: both checks have to happen before the payload is replaced,
		// otherwise the size comparison would compare the new payload against itself
		needsMoreSpace := len(newPayload) > len(existing.payload)
		atEndOfDataStore := header.isAtEndOfDataStore(*existing)

		newOffset := existing.offset
		if needsMoreSpace && !atEndOfDataStore {
			// need to allocate new space since the new payload
			// does not fit into the space of the existing entry,
			// and we can't grow it anymore since the current payload
			// is not at the very end of the data store.

			// Allocating before growing the entry keeps the allocator from
			// seeing this entry overlap the space it is about to hand out.
			newOffset = header.allocateSpaceInDatastore(uint32(len(newPayload)), format)
		}
		// otherwise the new payload either fits inside the space occupied by the
		// current payload OR that payload is at the very end of the data store,
		// so just growing it does not hurt

		existing.offset = newOffset
		existing.dataItemCnt = newDataItemCnt
		existing.payload = newPayload
		// the replaced payload almost never has the size of the old one, so every
		// entry behind it in the data store has to be moved
		header.syncDataStoreLayout()
		return
	}
	// no existing entry, add new
	header.addIndexEntry(IndexEntry{
		isMainHeaderEntry: header.IsMainHeader,
		tag:               tag.ID(),
		formatType:        uint32(format),
		dataItemCnt:       newDataItemCnt,
		payload:           newPayload,
	})
}

func (header *RpmHeader) Write(destination Serializer, isMainHeader bool) error {

	//if isMainHeader {
	//	RootLogger().Infof("Writing RPM header (main header) at offset 0x%x", destination.offset())
	//} else {
	//	RootLogger().Infof("Writing RPM header (signature header) at offset 0x%x", destination.offset())
	//}

	if isMainHeader {
		// main header needs to be aligned on an 8-bit boundary
		if err := destination.writeAlignTo(8); err != nil {
			return err
		}
	}

	/*
		     * The header structure header always starts with a three-byte Magic number: 8e ad e8.
			 *
		     * - Following this is a one-byte version number.
		     * - Next are four bytes that are reserved for future expansion.
		     * - After the reserved bytes, there is a four-byte number that indicates how many index entries exist in this header structure
		     * - followed by another four-byte number indicating how many bytes of data are part of the header structure.
		Magic             [3]uint8
		version           uint8
		reserved          [4]uint8
		indexEntryCount   uint32
		storeSizeInBytes  uint32
	*/
	if err := destination.writeBytes(header.Magic[:]); err != nil {
		return err
	}
	if err := destination.writeByte(header.version); err != nil {
		return err
	}
	if err := destination.writeBytes(header.reserved[:]); err != nil {
		return err
	}
	if err := destination.writeWord(header.indexEntryCount); err != nil {
		return err
	}
	if err := destination.writeWord(header.storeSizeInBytes); err != nil {
		return err
	}

	dataStoreData := NewDynamicArray()

	// write index entries
	for _, entry := range header.IndexEntries {
		/*
			// data from index entry
			tag         uint32 // The first four bytes contain a tag — a numeric value that identifies what type of data is pointed to by the entry.
			formatType  uint32 // Following the tag, is a four-byte type, which is a numeric value that describes the format of the data pointed to by the entry.
			offset      uint32 // Next is a four-byte offset that contains the position of the data, relative to the beginning of the store.
			dataItemCnt uint32 // STRING data always has a count of 1, while STRING_ARRAY data has a count equal to the number of strings contained in the store.
			// data of this index entry from the "data store"
			payload []byte
		*/
		if err := destination.writeWord(entry.tag); err != nil {
			return err
		}
		if err := destination.writeWord(entry.formatType); err != nil {
			return err
		}
		// verify correct alignment within dataStore
		alignment := FormatType(entry.formatType).GetRequiredAlignment()
		if entry.offset%uint32(alignment) != 0 {
			return fmt.Errorf("invalid format type alignment %d", entry.offset)
		}
		if err := destination.writeWord(entry.offset); err != nil {
			return err
		}
		if err := destination.writeWord(entry.dataItemCnt); err != nil {
			return err
		}
		if err := dataStoreData.Write(entry.payload, entry.offset); err != nil {
			panic(fmt.Sprintf("internal error while writing %d bytes of payload at offset 0x%x - %s", len(entry.payload), entry.offset, err))
		}
	}
	// write dataStore
	if err := destination.writeBytes(dataStoreData.GetData()); err != nil {
		return err
	}
	return nil
}

func (header *RpmHeader) GetMd5Digest() []byte {
	return header.Md5Digest.Sum([]byte{})
}

// GetData returns the full binary representation of this
// header as Write() would write it to an RPM file.
// This includes the header, the index table as
// well as the data store holding the index entry's data
func (header *RpmHeader) GetData() []byte {

	writer := NewArrayWriter()
	s := NewSerializer(nil, &writer)
	if err := header.Write(s, false); err != nil {
		panic(fmt.Sprintf("Internal error, writing header to []byte failed? %s", err.Error()))
	}
	return writer.Data
}

func (header *RpmHeader) GetSha1Digest() []byte {
	return header.Sha1Digest.Sum([]byte{})
}

func (header *RpmHeader) GetSha256Digest() []byte {
	return header.Sha256Digest.Sum([]byte{})
}

func (header *RpmHeader) FindIndexEntry(tag TagValue) *IndexEntry {

	// NOTE: must return a pointer to the slice element itself, not to the loop
	// variable, as callers mutate the entry through the returned pointer
	for idx := range header.IndexEntries {
		if header.IndexEntries[idx].tag == tag.ID() {
			return &header.IndexEntries[idx]
		}
	}
	return nil
}

func (lead *RpmLead) GetPackageType() PackageType {
	if lead.packageType == 0x00 {
		return PACKAGE_TYPE_BINARY
	}
	if lead.packageType == 0x01 {
		return PACKAGE_TYPE_SOURCE
	}
	panic("RPM has unknown package type")
}

func (lead *RpmLead) GetPackageName() string {
	return parseNullTerminatedStrings(lead.name[:])[0]
}

func validateDigests(rpm RpmFile, payloadMd5HasBeenCalculated bool) {

	/*
		All packages carry at least HEADERSIGNATURES, (LONG)SIZE, MD5 and SHA1, and since rpm >= 4.14, SHA256 tags.
	*/
	if rpm.SignatureHeader.SignedRegion == nil {
		panic("Signature header contained no signed/immutable region marker?")
	}

	actualEntries := len(rpm.SignatureHeader.IndexEntries)
	signedEntries := int(rpm.SignatureHeader.SignedRegion.IndexEntryCount)
	if actualEntries != signedEntries {
		panic(fmt.Sprintf("RPM has been tampered with ? Signature covers %d index entries but signature header has %d",
			signedEntries, actualEntries))
	}
	RootLogger().Debugf("Signature covers %d index entries and %d bytes of data", signedEntries, rpm.SignatureHeader.SignedRegion.Length)

	var err error
	md5Header := rpm.SignatureHeader.FindIndexEntry(SigTagMD5) // tag 1004, binary
	var sha1HashValue []byte
	var sha256HashValue []byte
	var sha1Header *IndexEntry
	var sha256Header *IndexEntry

	if sha1Header = rpm.SignatureHeader.FindIndexEntry(SigTagSHA1Header); sha1Header != nil { // tag 269, STRING
		sha1HashValue, err = hex.DecodeString(sha1Header.StringValue())
		if err != nil {
			panic("Failed to hex-decode SHA1 hash?")
		}
	}
	if sha256Header = rpm.SignatureHeader.FindIndexEntry(SigTagSHA256Header); sha256Header != nil { // tag 273, STRING
		sha256HashValue, err = hex.DecodeString(sha256Header.StringValue())
		if err != nil {
			panic("Failed to hex-decode SHA256 hash?")
		}
	}
	if md5Header == nil {
		panic("Invalid RPM file - no MD5 digest?")
	} else if payloadMd5HasBeenCalculated && !bytes.Equal(md5Header.payload, rpm.MainHeader.GetMd5Digest()) {
		panic(fmt.Sprintf("MD5 checksum validation failed, expected %s but got %s", hex.Dump(md5Header.payload), hex.Dump(rpm.MainHeader.GetMd5Digest())))
	}
	if sha1Header == nil {
		panic("Invalid RPM file - no SHA1 digest?")
	} else if !bytes.Equal(sha1HashValue, rpm.MainHeader.GetSha1Digest()) {
		expected := hex.Dump(sha1HashValue)
		actualBytes := rpm.MainHeader.GetSha1Digest()
		actual := hex.Dump(actualBytes)
		panic(fmt.Sprintf("SHA1 checksum validation failed, expected %s but got %s",
			expected,
			actual))
	}
	if sha256Header != nil && !bytes.Equal(sha256HashValue, rpm.MainHeader.GetSha256Digest()) {
		panic(fmt.Sprintf("SHA256 checksum validation failed, expected %s but got %s", hex.Dump(sha256Header.payload), hex.Dump(rpm.MainHeader.GetSha256Digest())))
	}

	// Inside an RPM package file, the **Signature Header** uses the standard RPM header data structure to store cryptographic digests, signatures, and size parameters.
	//
	//The fields represent the following data:
	//
	//* **`SHA1HEADER`** (Tag ID: `1012` or `RPMSIGTAG_SHA1`)
	//* **Contents:** A hex-encoded ASCII string representing the **SHA-1 message digest** calculated strictly over the **Header section** (the main metadata section, excluding the Signature Header and Payload).
	//* **Purpose:** Provides a lightweight header-integrity check.
	//
	//
	//* **`SHA256HEADER`** (Tag ID: `1016` or `RPMSIGTAG_SHA256`)
	//* **Contents:** A hex-encoded ASCII string representing the **SHA-256 message digest** calculated strictly over the **Header section**.
	//* **Purpose:** Modern replacement for `SHA1HEADER` to verify the main header’s integrity with stronger cryptography.
	//
	//
	//* **`SIG_SIZE`** (Tag ID: `1000` or `RPMSIGTAG_SIZE`)
	//* **Contents:** A 32-bit (or 64-bit) integer representing the **total byte size of the combined Header and Payload sections** (Header + Compressed Payload).
	//* **Purpose:** Used for basic structural sanity checks to verify the archive hasn't been truncated.
	//
	//
	//* **`SIG_MD5`** (Tag ID: `1004` or `RPMSIGTAG_PGP` / `RPMSIGTAG_MD5`)
	//* **Contents:** A 16-byte raw binary array containing the **MD5 checksum** calculated over the **combined Header and Payload sections**.
	//* **Purpose:** Legacy check (RPM v3) used to verify that neither the metadata nor the package payload suffered data corruption. Modern RPM systems still read this as a fallback package identifier.
	//
	//
	//* **`SIG_PAYLOADSIZE`** (Tag ID: `1007` or `RPMSIGTAG_PAYLOADSIZE`)
	//* **Contents:** An integer representing the **uncompressed size in bytes of the CPIO payload file archive** inside the package.
	//* **Purpose:** Informs the RPM installer how much disk space is required to extract the files prior to installation.
}
func parseIndexEntry(s Serializer, isMainHeaderEntry bool) (IndexEntry, error) {
	indexEntry := IndexEntry{isMainHeaderEntry: isMainHeaderEntry}
	var err error
	if indexEntry.tag, err = s.readWord(); err != nil {
		return indexEntry, err
	}
	if indexEntry.formatType, err = s.readWord(); err != nil {
		return indexEntry, err
	}
	if indexEntry.offset, err = s.readWord(); err != nil {
		return indexEntry, err
	}
	if indexEntry.dataItemCnt, err = s.readWord(); err != nil {
		return indexEntry, err
	}
	return indexEntry, nil
}

func validate(rpm RpmFile, validatePayloadMd5 bool) {

	rpm.Lead.GetPackageType()

	validateDigests(rpm, validatePayloadMd5)
}

func parseHeader(s Serializer, isMainHeader bool) (RpmHeader, error) {

	// parse first header
	hdr1 := RpmHeader{
		headerStartOffset: s.offset(),
		Sha1Digest:        sha1.New(),
		Sha256Digest:      sha256.New(),
		Md5Digest:         md5.New(),
		IsMainHeader:      isMainHeader,
	}

	// setup digest readers so we calculate digests as we go along
	if isMainHeader {
		originalReader := s.GetUnderlyingReader()

		md5Digest := NewDigestReaderImpl(originalReader, hdr1.Md5Digest)
		sha1Digest := NewDigestReaderImpl(md5Digest, hdr1.Sha1Digest)
		sha256Digest := NewDigestReaderImpl(sha1Digest, hdr1.Sha256Digest)

		s.SetUnderlyingReader(sha256Digest)
		defer func() {
			s.SetUnderlyingReader(originalReader)
		}()
	}

	// read magic
	err := s.readBytes(hdr1.Magic[:])
	if err != nil {
		return RpmHeader{}, err
	}
	if headerMagic != hdr1.Magic {
		return RpmHeader{}, errors.New("invalid RPM header header magic")
	}
	if hdr1.version, err = s.readByte(); err != nil {
		return RpmHeader{}, err
	}
	if err = s.readBytes(hdr1.reserved[:]); err != nil {
		return RpmHeader{}, err
	}
	if hdr1.indexEntryCount, err = s.readWord(); err != nil {
		return RpmHeader{}, err
	}
	RootLogger().Debugf("Number of index entries: %d\n", hdr1.indexEntryCount)
	if hdr1.storeSizeInBytes, err = s.readWord(); err != nil {
		return RpmHeader{}, err
	}

	hdr1.IndicesStartOffset = s.offset()
	// parse index entries
	for i := uint32(0); i < hdr1.indexEntryCount; i++ {
		entry, err := parseIndexEntry(s, isMainHeader)
		if err != nil {
			return RpmHeader{}, err
		}
		hdr1.IndexEntries = append(hdr1.IndexEntries, entry)
	}
	storeData := make([]byte, hdr1.storeSizeInBytes)
	hdr1.DataStoreStartOffset = s.offset()
	err = s.readBytes(storeData)
	if err != nil {
		return RpmHeader{}, fmt.Errorf("failed to read header data store. %w", err)
	}

	// sort header entries ascending by offset
	// as we're going to parse the whole store
	// starting from the beginning, skipping any
	// padding bytes in the process
	sortedEntryIndices := make([]int, len(hdr1.IndexEntries))
	for i := 0; i < len(hdr1.IndexEntries); i++ {
		sortedEntryIndices[i] = i
	}

	slices.SortFunc(sortedEntryIndices, func(a, b int) int {
		return cmp.Compare(hdr1.IndexEntries[a].offset, hdr1.IndexEntries[b].offset)
	})

	storeDataSerializer := NewSerializerFromArray(storeData)
	for _, idx := range sortedEntryIndices {
		entry := &hdr1.IndexEntries[idx]
		// fmt.Printf("--- Now parsing payload of IndexEntry #%d at offset 0x%x\n", idx, entry.offset)
		if storeDataSerializer.offset() > uint64(entry.offset) {
			panic("Already past start of entry ?")
		}
		if storeDataSerializer.offset() < uint64(entry.offset) {
			toSkip := uint64(entry.offset) - storeDataSerializer.offset()
			RootLogger().Debugf("Skipping %d padding bytes\n", toSkip)
			_ = os.Stdout.Sync()
			err = storeDataSerializer.readAhead(uint32(toSkip))
			if err != nil {
				return RpmHeader{}, err
			}
		}
		err = entry.populatePayload(storeDataSerializer)
		if err != nil {
			return RpmHeader{}, err
		}
		RootLogger().Debugf("Got index entry #%d : %s\n", idx, entry.String())
		if len(entry.payload) == 0 {
			panic("Empty payload?")
		}

		if !isMainHeader && entry.tag == SigTagHeaderSignatures.ID() {

			sigSer := NewSerializerFromArray(entry.payload)
			// tag = 0x3e
			value, err := sigSer.readWord()
			if err != nil || value != 0x3e {
				panic("Invalid SigTagHeaderSignatures entry (tag value)")
			}
			// type (binary = 7)
			value, err = sigSer.readWord()
			if err != nil || value != 0x7 {
				panic("Invalid SigTagHeaderSignatures entry (type)")
			}
			negativeOffset, err := sigSer.readWord()
			if err != nil {
				panic("Invalid SigTagHeaderSignatures entry (negative offset)")
			}
			byteCnt, err := sigSer.readWord()
			if err != nil || byteCnt != 16 {
				panic("Invalid SigTagHeaderSignatures entry (size)")
			}

			size := uint32(-int32(negativeOffset))
			hdr1.SignedRegion = &SignedRegion{
				IndexEntriesStartOffset: hdr1.DataStoreStartOffset - uint64(size),
				Length:                  uint64(hdr1.storeSizeInBytes + size),
				IndexEntryCount:         size / 16,
			}
			RootLogger().Debugf("Signed region: %s", hdr1.SignedRegion.String())
		}
	}

	if !isMainHeader {
		// we read the signature header, the main header
		// is always aligned on an 8-bit boundary
		err = s.advanceToNext8ByteBoundary()
		if err != nil {
			return hdr1, err
		}
	}
	return hdr1, nil
}

type IOReaderWithOffset struct {
	file          io.Reader
	currentOffset uint64
}

func NewIOReaderWithOffset(file io.Reader) ReaderWithOffset {
	return &IOReaderWithOffset{
		file: file,
	}
}

func (r *IOReaderWithOffset) Close() error {
	return Close(r.file)
}

func (r *IOReaderWithOffset) Read(p []byte) (n int, err error) {
	cnt, err := r.file.Read(p)
	if cnt > 0 {
		r.currentOffset += uint64(cnt)
	}
	return cnt, err
}

func (r *IOReaderWithOffset) Offset() uint64 {
	return r.currentOffset
}

func (lead *RpmLead) write(destination Serializer) error {

	RootLogger().Infof("Writing RPM lead at offset 0x%x", destination.offset())
	if err := destination.writeBytes(lead.Magic[:]); err != nil {
		return err
	}
	if err := destination.writeByte(lead.Major); err != nil {
		return err
	}
	if err := destination.writeByte(lead.Minor); err != nil {
		return err
	}
	if err := destination.writeShort(lead.packageType); err != nil {
		return err
	}
	if err := destination.writeShort(lead.ArchNum); err != nil {
		return err
	}
	if err := destination.writeBytes(lead.name[:]); err != nil {
		return err
	}
	if err := destination.writeShort(lead.OsNum); err != nil {
		return err
	}
	if err := destination.writeShort(lead.SignatureType); err != nil {
		return err
	}
	if err := destination.writeBytes(lead.Reserved[:]); err != nil {
		return err
	}
	return nil
}

func parseLead(s Serializer) (RpmLead, error) {

	// read magic
	lead := RpmLead{}

	err := s.readBytes(lead.Magic[:])
	if err != nil {
		return RpmLead{}, err
	}
	if leadMagic != lead.Magic {
		return RpmLead{}, fmt.Errorf("invalid RPM file magic. expected %s but got %s", hex.Dump(leadMagic[:]), hex.Dump(lead.Magic[:]))
	}
	RootLogger().Debugf("---------------> Parsing signature header starting at offset 0x%016x\n", s.offset())

	if lead.Major, err = s.readByte(); err != nil {
		return RpmLead{}, err
	}

	if lead.Minor, err = s.readByte(); err != nil {
		return RpmLead{}, err
	}

	if lead.packageType, err = s.readShort(); err != nil {
		return RpmLead{}, err
	}

	if lead.ArchNum, err = s.readShort(); err != nil {
		return RpmLead{}, err
	}

	err = s.readBytes(lead.name[:])
	if err != nil {
		return RpmLead{}, err
	}

	if lead.OsNum, err = s.readShort(); err != nil {
		return RpmLead{}, err
	}

	if lead.SignatureType, err = s.readShort(); err != nil {
		return RpmLead{}, err
	}

	if err = s.readBytes(lead.Reserved[:]); err != nil {
		return RpmLead{}, err
	}
	return lead, nil
}

// GetRpmVersion returns the version number of the 'rpm' CLI
// tool that was used to build this RPM
func (f *RpmFile) GetRpmVersion() string {
	index := f.MainHeader.FindIndexEntry(TagRpmversion)
	if index == nil {
		return ""
	}
	return index.StringValue()
}

// GetFileFormatVersion returns the RPM file format
// as given in the file's header.
func (f *RpmFile) GetFileFormatVersion() RpmFileFormatVersion {
	return RpmFileFormatVersion{
		Major: f.Lead.Major,
		Minor: f.Lead.Minor,
	}
}
func (f *RpmFile) IsSigned() bool {
	return !f.GetSignatureVersions().IsEmpty()
}

// GetSignatureVersions returns version numbers of all
// signatures found within this RPM file
func (f *RpmFile) GetSignatureVersions() Set[SignatureVersion] {
	result := NewSet[SignatureVersion]()

	hasV3 := f.SignatureHeader.FindIndexEntry(SigTagPGP) != nil || // 1002 & 1005
		f.SignatureHeader.FindIndexEntry(SigTagGPG) != nil
	hasV4 := f.SignatureHeader.FindIndexEntry(SigTagRSAHeader) != nil || // 267 & 268
		f.SignatureHeader.FindIndexEntry(SigTagDSAHeader) != nil
	hasV6 := f.SignatureHeader.FindIndexEntry(SigTagOpenPGP) != nil // 278

	if hasV3 {
		result.Add(SIGNATURE_VERSION_V3)
	}
	if hasV4 {
		result.Add(SIGNATURE_VERSION_V4)
	}
	if hasV6 {
		result.Add(SIGNATURE_VERSION_V6)
	}
	return result
}

func (f *RpmFile) WriteToFile(outputName string, payloadReader ReaderWithOffset) error {
	outFile, err := os.Create(outputName)
	if err != nil {
		return fmt.Errorf("failed to open() output file %v - %w", outputName, err)
	}
	defer func() { _ = outFile.Close() }()

	writer := NewFileWriterWithOffset(outFile)
	if err = f.Write(writer, payloadReader); err != nil {
		return fmt.Errorf("failed to write() %v - %w", outputName, err)
	}
	if err = outFile.Close(); err != nil {
		return fmt.Errorf("failed to close() %v - %w", outputName, err)
	}
	return nil
}

func (f *RpmFile) Write(destination WriterWithOffset, payload ReaderWithOffset) error {

	s := NewSerializer(nil, destination)

	if err := f.Lead.write(s); err != nil {
		return err
	}
	if err := f.SignatureHeader.Write(s, false); err != nil {
		return err
	}
	if err := f.MainHeader.Write(s, true); err != nil {
		return err
	}

	RootLogger().Infof("Writing RPM payload at offset 0x%x", destination.Offset())
	RootLogger().Infof("Reader ist at offset 0x%x", payload.Offset())
	bytesCopied, err := io.Copy(destination, payload)
	RootLogger().Infof("Copied %d payload bytes", bytesCopied)
	return err
}

func ParseRPMFromReader(reader ReaderWithOffset, validatePayloadM5 bool) (RpmFile, error) {
	return ParseRPM(NewSerializer(reader, nil), validatePayloadM5)
}

// ParseRPM an RPM file. If validatePayloadM5 == true, the reader
// needs to be able to provide the payload as well
func ParseRPM(reader Serializer, validatePayloadM5 bool) (RpmFile, error) {

	// parse lead
	lead, err := parseLead(reader)
	if err != nil {
		return RpmFile{}, err
	}

	// parse signature header
	RootLogger().Debugf("---------------> Parsing signature header starting at offset 0x%016x\n", reader.offset())
	sigHeader, err := parseHeader(reader, false)
	if err != nil {
		return RpmFile{}, err
	}

	// parse main header, beginning is ALWAYS padded to an 8-byte boundary
	RootLogger().Debugf("---------------> Parsing main header starting at offset 0x%016x\n", reader.offset())
	mainHeader, err := parseHeader(reader, true)
	if err != nil {
		return RpmFile{}, err
	}

	// main header is IMMEDIATELY followed by payload , NO PADDING
	sigSize := sigHeader.FindIndexEntry(SigTagSigSize) // tag 257
	if sigSize == nil {
		// fall-back to V3 header
		sigSize = sigHeader.FindIndexEntry(SigTagSize) // tag 1000
	}
	if sigSize == nil {
		panic("Failed to find SIG_SIZE entry")
	}
	mainHeaderSize := reader.offset() - mainHeader.headerStartOffset
	compressedPayloadSize := uint64(sigSize.Int32Value()) - mainHeaderSize

	rpm := RpmFile{
		Lead:                  lead,
		SignatureHeader:       sigHeader,
		MainHeader:            mainHeader,
		PayloadStartOffset:    reader.offset(),
		CompressedPayloadSize: compressedPayloadSize,
	}

	// read payload while updating the main header MD5 digest
	// that includes the main header AND the compressed payload
	if validatePayloadM5 {

		RootLogger().Debugf("Reading %d payload bytes", compressedPayloadSize)
		originalReader := reader.GetUnderlyingReader()
		md5Digest := NewDigestReaderImpl(originalReader, mainHeader.Md5Digest)
		reader.SetUnderlyingReader(md5Digest)
		err = reader.readAhead(uint32(compressedPayloadSize))
		reader.SetUnderlyingReader(originalReader)

		if err != nil {
			panic(fmt.Sprintf("Compressed payload seems to be truncated, expected at least %d bytes of payload", compressedPayloadSize))
		}
	}
	validate(rpm, validatePayloadM5)
	return rpm, nil
}
