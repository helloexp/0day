package giop

// ServiceContextList
// IIOP ServiceContextList
type ServiceContextList struct {
	SequenceLength []byte            // 4
	ServiceContext []*ServiceContext // SequenceLength
}

// ServiceContext
// IIOP ServiceContext
type ServiceContext struct {
	VSCID           []byte // 3
	SCID            []byte // 1
	_sequenceLength []byte // 4
	Endianness      []byte // 1
	Data            []byte // _sequenceLength-1
}
