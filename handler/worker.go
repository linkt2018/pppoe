package handler

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"math/rand"
	"pppoe-probe/pppoe"
	"strings"
	"sync"
)

type Worker struct {
	h             *Handler
	srcMac        []byte
	pppoesReqOnce sync.Once
	magicNumber   uint32
}

func NewWorker(h *Handler, srcMac []byte) *Worker {
	return &Worker{
		h:           h,
		srcMac:      srcMac,
		magicNumber: rand.Uint32(),
	}
}

func (w *Worker) handlePacket(packet gopacket.Packet) {
	ethPack, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	switch ethPack.EthernetType {
	case layers.EthernetTypePPPoEDiscovery:
		pppoed, err := pppoe.DecodePPPoED(ethPack.Payload)
		if err != nil {
			logrus.Errorln("failed to decode eth pppoed payload", err)
			return
		}
		logrus.Debugln("handle pppoe discovery", pppoed.Code, "from", ethPack.SrcMAC, fmt.Sprintf("%+v", pppoed))
		switch pppoed.Code {
		case pppoe.CodePADI:
			w.sendPPPoEDPacket(pppoe.NewPPPoEDPacket(pppoe.CodePADO, pppoed.SessionID, NovaDefaultAcName, pppoed.HostUniq, getRandCookie()))
		case pppoe.CodePADR:
			w.sendPPPoEDPacket(pppoe.NewPPPoEDPacket(pppoe.CodePADS, pppoed.SessionID+1, NovaDefaultAcName, pppoed.HostUniq, pppoed.AcCookie))
		}
	case layers.EthernetTypePPPoESession:
		pppoes, err := pppoe.DecodePPPoES(ethPack.Payload)
		if err != nil {
			logrus.Errorln("failed to decode eth pppoes payload", err)
			return
		}
		if pppoes.Code != pppoe.SCodeSessionData {
			logrus.Warnln("unknown session code", pppoes.Code)
			return
		}
		if pppoes.P2PProtocol == pppoe.P2PLinkCtrlProtocol {
			w.handleLinkCtrlProtocol(ethPack.SrcMAC, pppoes)
		} else if pppoes.P2PProtocol == pppoe.P2PAuthProtocol {
			w.handleAuthProtocol(ethPack.SrcMAC, pppoes)
		} else {
			logrus.Warnln("unknown p2p link protocol")
			return
		}
	}
}

func (w *Worker) handleLinkCtrlProtocol(srcMac []byte, pppoes pppoe.PPPoES) {
	logrus.Debugln("handle pppoe session", pppoes.LinkProtocol.GetShowCode(), "from", srcMac, fmt.Sprintf("%+v", pppoes))
	if pppoes.Code != pppoe.SCodeSessionData {
		logrus.Warnln("unknown session code", pppoes.Code)
		return
	}
	// 发送不带任何配置项的Request
	w.pppoesReqOnce.Do(func() {
		w.sendPPPoESPacket(pppoe.NewPPPoESLinkProtocolPacket(0x01,
			pppoe.AuthProtocolPassword,
			pppoe.LinkCodeConfigRequest,
			pppoes.LinkProtocol.Identifier+1,
			pppoes.LinkProtocol.MaxReceiveUint,
			w.magicNumber,
			false,
			false,
			0))
	})
	switch pppoes.LinkProtocol.Code {
	case pppoe.LinkCodeConfigRequest:
		if pppoes.LinkProtocol.AddressCtrlFieldCompression || pppoes.LinkProtocol.ProtocolFieldCompression || pppoes.LinkProtocol.CallbackOperation != 0 {
			// Reject所有的配置项
			w.sendPPPoESPacket(pppoe.NewPPPoESLinkProtocolPacket(pppoes.SessionID,
				0,
				pppoe.LinkCodeConfigReject,
				pppoes.LinkProtocol.Identifier,
				0,
				0,
				pppoes.LinkProtocol.ProtocolFieldCompression,
				pppoes.LinkProtocol.AddressCtrlFieldCompression,
				pppoes.LinkProtocol.CallbackOperation))
			return
		}
		// Accept不带配置项的请求
		w.sendPPPoESPacket(pppoe.NewPPPoESLinkProtocolPacket(0x01,
			pppoes.LinkProtocol.AuthProtocol,
			pppoe.LinkCodeConfigAck,
			pppoes.LinkProtocol.Identifier,
			pppoes.LinkProtocol.MaxReceiveUint,
			pppoes.LinkProtocol.MagicNumber,
			pppoes.LinkProtocol.ProtocolFieldCompression,
			pppoes.LinkProtocol.AddressCtrlFieldCompression,
			pppoes.LinkProtocol.CallbackOperation))

	case pppoe.LinkCodeConfigReject:
	case pppoe.LinkCodeConfigAck:

	}
}

func getRandCookie() (bs []byte) {
	for i := 0; i < 20; i++ {
		bs = append(bs, byte(rand.Int()))
	}
	return
}

func (w *Worker) sendPPPoESPacket(pppoes pppoe.PPPoES) {
	if pppoes.P2PProtocol == pppoe.P2PLinkCtrlProtocol {
		logrus.Debugln("send pppoe session link ctrl", pppoes.LinkProtocol.GetShowCode(), "to", w.srcMac, fmt.Sprintf("%+v", pppoes))
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	payload := pppoes.Encode()
	_ = gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       w.h.adapterMac,
			DstMAC:       w.srcMac,
			EthernetType: layers.EthernetTypePPPoESession,
		},
		gopacket.Payload(payload),
	)
	data := buffer.Bytes()
	err := w.h.handle.WritePacketData(data)
	if err != nil {
		fmt.Println("write packet data", err)
	}
}

func (w *Worker) sendPPPoEDPacket(pppoed pppoe.PPPoED) {
	logrus.Debugln("send pppoe discovery", pppoed.Code, "to", mac(w.srcMac), fmt.Sprintf("%+v", pppoed))
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	payload := pppoed.Encode()
	_ = gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       w.h.adapterMac,
			DstMAC:       w.srcMac,
			EthernetType: layers.EthernetTypePPPoEDiscovery,
		},
		gopacket.Payload(payload),
	)
	data := buffer.Bytes()
	err := w.h.handle.WritePacketData(data)
	if err != nil {
		logrus.Errorln("write packet data", err)
	}
}

func (w *Worker) handleAuthProtocol(srcMac []byte, pppoes pppoe.PPPoES) {
	logrus.Debugln("handle pppoe session", pppoes.PwdAuthProtocol.GetShowCode(), "from", srcMac, "user:", pppoes.PwdAuthProtocol.PeerID)
	w.h.workerDone <- &Auth{
		PeerID:   pppoes.PwdAuthProtocol.PeerID,
		Password: pppoes.PwdAuthProtocol.Password,
	}
}

func mac(bs []byte) string {
	var buf []string
	str := hex.EncodeToString(bs)
	for i := 0; i < len(str); i++ {
		if (i+1)%2 == 0 && i < len(str) {
			buf = append(buf, str[i-1:i+1])
		}
	}
	return strings.Join(buf, ":")
}
