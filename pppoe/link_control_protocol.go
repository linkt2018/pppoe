package pppoe

import (
	"encoding/binary"
	"errors"
)

type LinkCode byte

const LinkCodeConfigRequest LinkCode = 0x01
const LinkCodeConfigAck LinkCode = 0x02
const LinkCodeConfigNak LinkCode = 0x03
const LinkCodeConfigReject LinkCode = 0x04
const LinkCodeEchoRequest LinkCode = 0x09

type Option byte

const (
	OptionMaxReceiveUint                    Option = 0x1
	OptionAuthProtocol                      Option = 0x3
	OptionMagicNumber                       Option = 0x5
	OptionProtocolFieldCompression          Option = 0x7
	OptionAddressAndControlFieldCompression Option = 0x8
	OptionCallback                          Option = 0xd
)

type CallbackOperation byte

const CallbackOperationCBCP CallbackOperation = 0x6

type AuthProtocol uint16

const AuthProtocolPassword AuthProtocol = 0xc023

type LinkCtrlProtocol struct {
	Code                        LinkCode
	Identifier                  byte
	MaxReceiveUint              uint16
	AuthProtocol                AuthProtocol
	MagicNumber                 uint32
	ProtocolFieldCompression    bool
	AddressCtrlFieldCompression bool
	CallbackOperation           CallbackOperation
}

func (p *LinkCtrlProtocol) GetShowCode() string {
	switch p.Code {
	case LinkCodeConfigAck:
		return "Config ACK"
	case LinkCodeConfigRequest:
		return "Config Request"
	case LinkCodeConfigReject:
		return "Config Reject"
	case LinkCodeEchoRequest:
		return "Echo Request"
	}
	return "Unknown"
}

func DecodeLinkCtrlProtocol(payload []byte) (p LinkCtrlProtocol, err error) {
	p.Code = LinkCode(payload[0])
	p.Identifier = payload[1]
	optionLen := binary.BigEndian.Uint16(payload[2:4])
	if optionLen == 0 {
		return
	}
	// link control options
	payload = payload[P2PProtocolBasicLen:]
	if len(payload) < int(optionLen)-P2PProtocolBasicLen {
		err = errors.New("invalid linkctrl options length")
		return
	}
	for {
		if len(payload) < 1 {
			break
		}
		if len(payload) < LinkCtrlOptionBasicLen {
			if payload[0] == 0 {
				return
			}
			err = errors.New("invalid option length")
			return
		}
		lType := Option(payload[0])
		lLen := payload[1]
		if lLen == 0 {
			payload = payload[LinkCtrlOptionBasicLen:]
			continue
		}
		if len(payload) < int(lLen) {
			err = errors.New("invalid option item length")
			return
		}

		switch lType {
		case OptionAddressAndControlFieldCompression:
			p.AddressCtrlFieldCompression = true
		case OptionProtocolFieldCompression:
			p.ProtocolFieldCompression = true
		case OptionMaxReceiveUint:
			if lLen != 4 {
				err = errors.New("invalid option max receive uint length")
				return
			}
			p.MaxReceiveUint = binary.BigEndian.Uint16(payload[2:lLen])
		case OptionMagicNumber:
			if lLen != 6 {
				err = errors.New("invalid option magic number length")
				return
			}
			p.MagicNumber = binary.BigEndian.Uint32(payload[2:lLen])
		case OptionCallback:
			if lLen != 3 {
				err = errors.New("invalid option callback length")
				return
			}
			p.CallbackOperation = CallbackOperation(payload[2])
		case OptionAuthProtocol:
			if lLen != 4 {
				err = errors.New("invalid option auth protocol length")
				return
			}
			p.AuthProtocol = AuthProtocol(binary.BigEndian.Uint16(payload[2:4]))
		}
		payload = payload[lLen:]
	}
	return
}
