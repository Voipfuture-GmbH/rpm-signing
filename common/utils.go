package common

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func IsPowerOfTwo(value uint64) bool {
	return (value & (value - 1)) == 0
}

type Set[T comparable] interface {
	Add(element T) bool
	Contains(element T) bool
	IsEmpty() bool
	Size() int
	String() string
	Members() []T
}

type SetImpl[T comparable] struct {
	elements map[T]struct{}
}

var _ Set[any] = (*SetImpl[any])(nil)

func (s *SetImpl[T]) String() string {
	var result []string

	for key := range s.elements {
		result = append(result, fmt.Sprintf("%v", key))
	}
	return strings.Join(result, ", ")
}

func (s *SetImpl[T]) Members() []T {
	return slices.Collect(maps.Keys(s.elements))
}

func (s *SetImpl[T]) Size() int {
	return len(s.elements)
}
func (s *SetImpl[T]) IsEmpty() bool {
	return s.Size() == 0
}

func (s *SetImpl[T]) Add(element T) bool {
	if s.Contains(element) {
		return false
	}
	s.elements[element] = struct{}{}
	return true
}

func (s *SetImpl[T]) Contains(element T) bool {
	_, ok := s.elements[element]
	return ok
}

func NewSet[T comparable]() Set[T] {
	v := SetImpl[T]{elements: make(map[T]struct{})}
	return &v
}

// CalcAlignmentByteCount calculates the INCREMENT (in bytes)
// that needs to be added to the given address to achieve
// the requested alignment (1
func CalcAlignmentByteCount(address uint64, alignment uint8) uint8 {
	if alignment == 1 {
		return 0
	}
	if alignment == 0 || !IsPowerOfTwo(uint64(alignment)) {
		panic("Invalid alignment: " + strconv.Itoa(int(alignment)))
	}
	v1 := uint64(alignment)
	v2 := uint64(alignment - 1)
	paddingNeeded := (v1 - (address & v2)) & v2
	return uint8(paddingNeeded)
}

func growLen[S ~[]E, E any](s S, targetLen int) S {
	if len(s) >= targetLen {
		return s
	}
	n := make(S, targetLen)
	copy(n, s)
	return n
}

// GrowSliceIfNecessary increases the capacity of a given slice if necessary
// to not fail when accessing a given index within that slice
func GrowSliceIfNecessary[S ~[]E, E any](index uint32, arrayToGrow *S) {
	currentLen := uint32(len(*arrayToGrow))

	if index >= currentLen {
		// need to grow internal array
		newLen := 1 + uint32(len(*arrayToGrow)*2)
		if newLen <= index {
			newLen = index + 1
		}
		*arrayToGrow = growLen(*arrayToGrow, int(newLen))
	}
}

// SeekableReader combines ReaderWithOffset with a function
// to see to an offset relative to the start of the input stream.
// Depending on the actual implementation it may not be possible
// to seek back all the way to the very beginning of the input stream
// but only a limited distance.
type SeekableReader interface {
	ReaderWithOffset
	SeekRelativeToStart(offset int64) (err error)
}

type SeekableReaderImpl struct {
	reader ReaderWithOffset
}

var _ SeekableReader = (*SeekableReaderImpl)(nil)

func (s *SeekableReaderImpl) Close() error {
	return s.reader.Close()
}

func (s *SeekableReaderImpl) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

func (s *SeekableReaderImpl) Offset() uint64 {
	return s.reader.Offset()
}

func (s *SeekableReaderImpl) SeekRelativeToStart(offset int64) (err error) {

	if readerWithOffset, ok := s.reader.(*IOReaderWithOffset); ok {
		wrappedReader := readerWithOffset.file
		if fileReader, ok := wrappedReader.(*os.File); ok {
			newOffset, err := fileReader.Seek(offset, 0)
			if err != nil {
				return fmt.Errorf("seek to offset %d failed: %w", offset, err)
			}
			if newOffset != offset {
				return fmt.Errorf("seek to offset %d failed, only reached %d", offset, newOffset)
			}
			return err
		}
	}
	if offset < 0 {
		return errors.New("seek() with negative offset only supported for files")
	}
	if s.reader.Offset() != 0 {
		return errors.New("seek() with from beginning of stream only supported if stream is still at offset 0")
	}
	buf := make([]byte, offset)
	return FillBuffer(buf, s.reader)
}

func NewSeekableReader(reader ReaderWithOffset) SeekableReader {
	return &SeekableReaderImpl{reader: NewIOReaderWithOffset(reader)}
}

func OpenFileOrUrl(rpmFilePath string) (SeekableReader, error) {
	if strings.HasPrefix(strings.ToLower(rpmFilePath), "http") ||
		strings.HasPrefix(strings.ToLower(rpmFilePath), "https") {
		reader, err := DownloadFile(rpmFilePath)
		if err != nil {
			panic(err)
		}
		return NewSeekableReader(NewIOReaderWithOffset(reader)), nil
	}
	file, err := os.OpenFile(rpmFilePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		panic(err)
	}
	return NewSeekableReader(NewIOReaderWithOffset(file)), nil
}

func IsFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

func IsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func RemoveAtIndex[T any](s []T, index int) []T {
	return append(s[:index], s[index+1:]...)
}

func ListMatchingFiles(paths []string, regex string) ([]string, error) {

	result := make([]string, 0)
	for _, path := range paths {

		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		compiled := regexp.MustCompile(regex)
		for _, entry := range entries {

			if !entry.IsDir() {
				if compiled.MatchString(entry.Name()) {
					result = append(result, filepath.Join(path, entry.Name()))
				}
			}
		}
	}
	return result, nil
}

func DownloadFile(url string) (io.ReadCloser, error) {
	// 1. Get the data
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}
	return resp.Body, err
}

func FillBuffer(buf []byte, reader io.Reader) error {

	bytesRead := 0
	remaining := len(buf)
	for remaining > 0 {
		cnt, err := reader.Read(buf[bytesRead:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				remaining -= cnt
				if remaining > 0 {
					return fmt.Errorf("expected %d bytes but only got %d", len(buf), cnt)
				}
				return nil
			}
			return err
		}
		bytesRead += cnt
		remaining -= cnt
	}
	return nil
}

func RightPad(s string, padChar string, totalLength int) string {
	// Use RuneCountInString so multibyte UTF-8 characters are measured accurately
	charCount := utf8.RuneCountInString(s)
	if charCount >= totalLength {
		return s
	}
	return s + strings.Repeat(padChar, totalLength-charCount)
}

func CenterPad(s string, padChar string, totalLength int) string {
	// Use RuneCountInString so multibyte UTF-8 characters are measured accurately
	charCount := utf8.RuneCountInString(s)
	if charCount >= totalLength {
		return s
	}
	delta := totalLength - charCount
	deltaLeft := delta / 2
	deltaRight := totalLength - charCount - deltaLeft

	return strings.Repeat(padChar, deltaLeft) + s + strings.Repeat(padChar, deltaRight)
}

// RandomString generates a random string of the given length
func RandomString(length int, allowedLetters string) (string, error) {
	b := make([]byte, length)
	lettersLen := big.NewInt(int64(len(allowedLetters)))

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, lettersLen)
		if err != nil {
			return "", err
		}
		b[i] = allowedLetters[num.Int64()]
	}

	return string(b), nil
}

func CloseWriter(writer io.Writer) error {
	if writer != nil {
		closeable, ok := writer.(io.Closer)
		if ok {
			return closeable.Close()
		}
		// ok, cannot be closed
	}
	return nil
}

func Close(reader io.Reader) error {
	if reader != nil {
		closeable, ok := reader.(io.Closer)
		if ok {
			return closeable.Close()
		}
		// ok, cannot be closed
	}
	return nil
}

func CloseQuietly(reader io.Reader) {
	_ = Close(reader)
}

func ReadLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func WriteFileAtomically(filename string, data []byte, perm os.FileMode, overwrite bool) error {

	var err error
	destinationExists, err := FileExists(filename)
	if err != nil {
		return err
	}
	if destinationExists && !overwrite {
		return fmt.Errorf("destination file %s already exists and overwriting not enabled", filename)
	}

	dir := filepath.Dir(filename)

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// scheduled cleanup on failure
	defer func() {
		if err != nil {
			CloseQuietly(tmpFile)
			_ = os.Remove(tmpFile.Name())
		}
	}()

	if _, err = tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err = tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err = tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err = os.Rename(tmpFile.Name(), filename); err != nil {
		return fmt.Errorf("failed to replace target file: %w", err)
	}

	return nil
}
