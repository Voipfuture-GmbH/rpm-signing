package common

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

type OffsetProvider interface {
	Offset() uint64
}

type Rewindable interface {
	Rewind() error
}

type RewindableReader interface {
	io.Reader
	io.Closer
	Rewind() error
}

type RewindableReaderWithOffset interface {
	RewindableReader
	OffsetProvider
}

// WriterWithOffset is an io.Writer that tracks the
// current write offset
type WriterWithOffset interface {
	io.Writer
	io.Closer
	OffsetProvider
}

type DelegatingReader interface {
	io.Reader
	GetDelegate() io.Reader
}

// ReaderWithOffset is an io.Reader that tracks the
// current read offset
type ReaderWithOffset interface {
	io.Reader
	io.Closer
	OffsetProvider
}

type DigestReader interface {
	DelegatingReader
	ReaderWithOffset
	GetDigest() []byte
}

type FileWriterWithOffset struct {
	file          *os.File
	currentOffset uint64
}

var _ WriterWithOffset = (*FileWriterWithOffset)(nil)

func (w *FileWriterWithOffset) Close() error {
	return w.file.Close()
}

func (w *FileWriterWithOffset) Write(p []byte) (n int, err error) {
	cnt, err := w.file.Write(p)
	if err != nil {
		return cnt, err
	}
	w.currentOffset += uint64(cnt)
	if cnt != len(p) {
		return cnt, io.ErrShortWrite
	}
	return len(p), nil
}
func (w *FileWriterWithOffset) Offset() uint64 {
	return w.currentOffset
}

func NewFileWriterWithOffset(file *os.File) *FileWriterWithOffset {
	return &FileWriterWithOffset{file: file}
}

type DigestReaderImpl struct {
	source ReaderWithOffset
	digest hash.Hash
}

var _ DigestReader = (*DigestReaderImpl)(nil)
var _ ReaderWithOffset = (*DigestReaderImpl)(nil)
var _ WriterWithOffset = (*offsetTrackingWriter)(nil)

func (d *DigestReaderImpl) GetDelegate() io.Reader {
	return d.source
}

func (d *DigestReaderImpl) Close() error {
	return d.source.Close()
}

func (d *DigestReaderImpl) GetDigest() []byte {
	return d.digest.Sum(nil)
}

func (d *DigestReaderImpl) Offset() uint64 {
	return d.source.Offset()
}

func (d *DigestReaderImpl) Read(destination []byte) (n int, err error) {
	cnt, err := d.source.Read(destination)
	if cnt == len(destination) {
		d.digest.Write(destination)
	} else if cnt > 0 {
		d.digest.Write(destination[0:cnt])
	}
	return cnt, err
}

func NewDigestReaderImpl(source ReaderWithOffset, hash hash.Hash) *DigestReaderImpl {
	return &DigestReaderImpl{
		source: source,
		digest: hash,
	}
}

type Serializer interface {
	io.Closer
	GetUnderlyingReader() ReaderWithOffset
	GetUnderlyingWriter() io.Writer
	SetUnderlyingReader(reader ReaderWithOffset)
	// reading
	readByteArray(len uint32) ([]byte, error)
	readByte() (uint8, error)
	readShort() (uint16, error)
	readWord() (uint32, error)
	readLongWord() (uint64, error)
	readBytes(buf []byte) error
	readNullTerminatedString() ([]byte, error)

	// writing
	writeBytes(data []byte) error
	writeByte(d uint8) error
	writeShort(d uint16) error
	writeWord(d uint32) error
	writeLongWord(d uint64) error

	// writeAlignTo pads the output with zero bytes so that
	// the given address/offset alignment is achieved
	writeAlignTo(alignment uint8) error

	// misc
	offset() uint64
	// readAhead consumes a given number of bytes from the input stream.
	// this method INTENTIONALLY does not use Seek() etc. because its
	// being used to calculate message digests by invoking Read()
	// on a DigestReader
	readAhead(numBytes uint32) error
	advanceToNext8ByteBoundary() error
}

type SerializerImpl struct {
	reader ReaderWithOffset
	writer WriterWithOffset
}

var _ Serializer = (*SerializerImpl)(nil)

func (s *SerializerImpl) Close() error {
	err1 := s.reader.Close()
	err2 := s.writer.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
func (s *SerializerImpl) GetUnderlyingWriter() io.Writer {
	return s.writer
}

func (s *SerializerImpl) GetUnderlyingReader() ReaderWithOffset {
	return s.reader
}

func (s *SerializerImpl) SetUnderlyingReader(reader ReaderWithOffset) {
	s.reader = reader
}

func (s *SerializerImpl) writeAlignTo(alignment uint8) error {

	numBytesToWrite := CalcAlignmentByteCount(s.writer.Offset(), alignment)
	if numBytesToWrite != 0 {
		paddingBytes := make([]byte, numBytesToWrite)
		bytesWritten, err := s.writer.Write(paddingBytes)
		if err != nil {
			return err
		}
		if bytesWritten != len(paddingBytes) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *SerializerImpl) advanceToNext8ByteBoundary() error {
	numBytesToSkip := CalcAlignmentByteCount(s.reader.Offset(), 8)
	if numBytesToSkip != 0 {
		return s.readAhead(uint32(numBytesToSkip))
	}
	return nil
}

func (s *SerializerImpl) readNullTerminatedString() ([]byte, error) {
	var result []byte
	for {
		b, err := s.readByte()
		if err != nil {
			return result, err
		}
		result = append(result, b)
		if b == 0 {
			break
		}
	}
	return result, nil
}

func parseNullTerminatedStrings(data []uint8) []string {

	// If data ends with a null byte, Split leaves an empty slice at the end
	if len(data) == 0 {
		return nil
	}

	var builder strings.Builder
	var result = []string{}
	for _, value := range data {
		if value == 0 {
			result = append(result, builder.String())
			builder.Reset()
		} else {
			builder.WriteByte(value)
		}
	}
	return result
}

func (s *SerializerImpl) internalRead(buf []byte) (int, error) {
	cnt, err := s.reader.Read(buf)
	return cnt, err
}

func (s *SerializerImpl) readBytes(buf []byte) error {
	return FillBuffer(buf, s.reader)
}

func (s *SerializerImpl) writeBytes(data []byte) error {
	written, err := s.writer.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *SerializerImpl) readByteArray(len uint32) ([]byte, error) {
	var result = make([]byte, len)
	err := FillBuffer(result, s.reader)
	return result, err
}

func (s *SerializerImpl) offset() uint64 {
	if s.reader != nil {
		if s.writer != nil {
			panic("Both reader and writer are set - don't know which offset to return")
		}
		return s.reader.Offset()
	}
	if s.writer != nil {
		if s.reader != nil {
			panic("Both reader and writer are set - don't know which offset to return")
		}
		return s.writer.Offset()
	}
	panic("Neither reader nor writer are set ?")
}

func (s *SerializerImpl) readAhead(n uint32) error {
	if n == 0 {
		return nil
	}
	if n <= 100*1024 {
		scratchBuffer := make([]byte, n)
		err := FillBuffer(scratchBuffer, s.reader)
		if err != nil {
			return err
		}
		return nil
	}
	scratchBuffer := make([]byte, 100*1024)
	remaining := n
	for remaining > 0 {

		if remaining < uint32(cap(scratchBuffer)) {
			scratchBuffer = make([]byte, remaining)
		}
		bytesRead, err := s.reader.Read(scratchBuffer)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		remaining -= uint32(bytesRead)

		if bytesRead < cap(scratchBuffer) {
			break
		}
	}
	if remaining > 0 {
		return fmt.Errorf("input data truncated ? Tried to read %d bytes, expected %d more bytes", n, remaining)
	}
	return nil
}

func (s *SerializerImpl) writeByte(d uint8) error {
	n, err := s.writer.Write([]byte{d})
	if err != nil {
		return err
	}
	if uint32(n) != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func (s *SerializerImpl) writeShort(d uint16) error {
	if err := s.writeByte(uint8(d >> 8)); err != nil {
		return err
	}
	return s.writeByte(uint8(d))
}

func (s *SerializerImpl) writeWord(d uint32) error {
	if err := s.writeShort(uint16(d >> 16)); err != nil {
		return err
	}
	return s.writeShort(uint16(d))
}

func (s *SerializerImpl) writeLongWord(d uint64) error {
	if err := s.writeWord(uint32(d >> 32)); err != nil {
		return err
	}
	return s.writeWord(uint32(d))
}

func (s *SerializerImpl) readByte() (uint8, error) {
	buf := make([]uint8, 1)
	err := s.readBytes(buf)
	if err != nil {
		return 0, err
	}
	return buf[0], err
}

// RPM uses big-endian (MSB comes first)
func (s *SerializerImpl) readShort() (uint16, error) {
	buf := make([]uint8, 2)
	err := s.readBytes(buf)
	if err != nil {
		return 0, err
	}
	return uint16(buf[0])<<8 | uint16(buf[1]), nil
}

func (s *SerializerImpl) readWord() (uint32, error) {

	high, err := s.readShort()
	if err != nil {
		return 0, err
	}
	low, err := s.readShort()
	if err != nil {
		return 0, err
	}
	return uint32(high)<<16 | uint32(low), nil
}

func (s *SerializerImpl) readLongWord() (uint64, error) {

	high, err := s.readWord()
	if err != nil {
		return 0, err
	}
	low, err := s.readWord()
	if err != nil {
		return 0, err
	}
	return uint64(high)<<32 | uint64(low), nil
}

type ArrayWriter struct {
	Data          []uint8
	currentOffset uint64
}

func NewArrayWriter() ArrayWriter {
	return ArrayWriter{
		Data: make([]uint8, 0),
	}
}

func (arr *ArrayWriter) Close() error {
	return nil
}

func (arr *ArrayWriter) Write(p []byte) (n int, err error) {
	arr.Data = append(arr.Data, p...)
	arr.currentOffset += uint64(len(p))
	return len(p), nil
}

func (arr *ArrayWriter) Offset() uint64 {
	return arr.currentOffset
}

type arrayReader struct {
	src           []uint8
	currentOffset int
}

func NewArrayReader(data []uint8) RewindableReaderWithOffset {
	return &arrayReader{
		src: data,
	}
}

func (arr *arrayReader) Rewind() error {
	arr.currentOffset = 0
	return nil
}

func (arr *arrayReader) Close() error {
	return nil
}

func (arr *arrayReader) Offset() uint64 {
	return uint64(arr.currentOffset)
}

func (arr *arrayReader) Read(destination []byte) (n int, err error) {
	if len(destination) == 0 {
		return 0, nil
	}
	cntToCopy := len(destination)
	remaining := len(arr.src) - arr.currentOffset
	if remaining < len(destination) {
		cntToCopy = remaining
	}
	for srcOffset, dstOffset, cnt := arr.currentOffset, 0, cntToCopy; cnt > 0; cnt-- {
		destination[dstOffset] = arr.src[srcOffset]
		dstOffset++
		srcOffset++
	}
	arr.currentOffset += cntToCopy

	if cntToCopy < len(destination) {
		return cntToCopy, io.EOF
	}
	return cntToCopy, nil
}

func NewSerializerFromArray(data []uint8) Serializer {
	r := arrayReader{src: data, currentOffset: 0}
	return NewSerializer(&r, nil)
}

type offsetTrackingWriter struct {
	writer        io.Writer
	currentOffset uint64
}

func NewOffsetTrackingWriter(writer io.Writer) WriterWithOffset {
	return &offsetTrackingWriter{
		writer: writer,
	}
}

func (ow *offsetTrackingWriter) Close() error {
	return CloseWriter(ow.writer)
}

func (ow *offsetTrackingWriter) Write(p []byte) (n int, err error) {
	n, err = ow.writer.Write(p)
	ow.currentOffset += uint64(n)
	return n, err
}

func (ow *offsetTrackingWriter) Offset() uint64 {
	return ow.currentOffset
}

func NewSerializer(reader ReaderWithOffset, writer io.Writer) Serializer {
	var v SerializerImpl
	if writer != nil {
		v = SerializerImpl{reader: reader, writer: NewOffsetTrackingWriter(writer)}
	} else {
		v = SerializerImpl{reader: reader}
	}
	return &v
}
