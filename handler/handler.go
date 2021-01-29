package handler

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"pppoe-probe/goroutine"
	"pppoe-probe/pppoe"
	"time"
)

const NovaDefaultAcName = "nova-tools"

type Auth struct {
	PeerID   string
	Password string
}

// Handler 网络封包处理器。
// 一个处理器仅绑定一个网卡，启动后处理该网卡的所有封包。并通过 handler.Listener 函数回传事件。
// 各个方法都不支持并发调用。GUI 界面的并发在 GUI 那边用弹窗等待的方式处理掉了。
type Handler struct {
	adapterName string
	adapterMac  []byte
	handle      *pcap.Handle
	mac2Worker  map[string]*Worker
	workerDone  chan *Auth
	cb          Listener
	running     bool
}

func NewHandler(AdapterName string, adapterMac []byte, cb Listener) (h *Handler) {
	h = &Handler{}
	h.adapterName = AdapterName
	h.mac2Worker = make(map[string]*Worker)
	h.adapterMac = adapterMac
	h.workerDone = make(chan *Auth, 1)
	h.cb = cb

	var err error
	h.handle, err = pcap.OpenLive(h.adapterName, 1024, false, time.Second*10)
	if err != nil {
		h.callback(EventError, fmt.Sprintf("初始化适配器(%s)监听器失败：%s", mac(h.adapterMac), err.Error()))
		return
	}
	return
}

// Run 阻塞函数。会一直等待 worker 回传认证数据。
func (h *Handler) Run() {
	logrus.Infoln("start watching network adapter:", mac(h.adapterMac))
	h.callback(EventStart, mac(h.adapterMac))
	defer h.callback(EventStop, mac(h.adapterMac))

	goroutine.Go(func() {
		if h.handle == nil {
			return
		}
		packetSource := gopacket.NewPacketSource(h.handle, h.handle.LinkType())
		for packet := range packetSource.Packets() {
			h.Handle(packet)
		}
	})
	for d := range h.workerDone {
		h.callback(EventSessionAuthRequest, d.PeerID, d.Password)
	}
	logrus.Infoln("handler for", mac(h.adapterMac), "closed")
}

// Close 阻塞函数。pcap handle 启动后调用 Close 会阻塞几秒钟。
func (h *Handler) Close() {
	start := time.Now()
	h.handle.Close()
	h.handle = nil
	close(h.workerDone)
	logrus.Infoln("close handler for", mac(h.adapterMac), "use time:", time.Now().Sub(start).Milliseconds())
}

func (h *Handler) Handle(packet gopacket.Packet) {
	ethPack, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	key := hex.EncodeToString(ethPack.SrcMAC)
	switch ethPack.EthernetType {
	case layers.EthernetTypePPPoEDiscovery:
		pppoePack, _ := packet.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
		switch pppoePack.Code {
		case layers.PPPoECodePADI:
			if _, ok := h.mac2Worker[key]; ok {
				return
			}
			h.mac2Worker[key] = NewWorker(h, ethPack.SrcMAC)
			h.callback(EventDiscoveryBroadcast, mac(h.adapterMac), mac(ethPack.SrcMAC))
		case layers.PPPoECodePADR:
			h.callback(EventDiscoverySessionConfirmation, mac(h.adapterMac), mac(ethPack.SrcMAC))
		}
	case layers.EthernetTypePPPoESession:
		if _, ok := h.mac2Worker[key]; !ok {
			return
		}

		pppoes, err := pppoe.DecodePPPoES(ethPack.Payload)
		if err != nil {
			return
		}
		switch pppoes.P2PProtocol {
		case pppoe.P2PLinkCtrlProtocol:
			switch pppoes.LinkProtocol.Code {
			case pppoe.LinkCodeConfigRequest:
				h.callback(EventSessionRequest, mac(h.adapterMac), mac(ethPack.SrcMAC))
			case pppoe.LinkCodeConfigAck:
				h.callback(EventSessionACK, mac(h.adapterMac), mac(ethPack.SrcMAC))
			case pppoe.LinkCodeConfigNak:
				h.callback(EventSessionNak, mac(h.adapterMac), mac(ethPack.SrcMAC))
			}
		case pppoe.P2PAuthProtocol:
			h.callback(EventSessionAuthRequest, mac(h.adapterMac), mac(ethPack.SrcMAC))
		}
	}
	if c, ok := h.mac2Worker[key]; ok {
		c.handlePacket(packet)
		return
	}
}

func (h *Handler) callback(e Event, args ...interface{}) {
	if h.cb != nil {
		h.cb(e, args...)
	}
}
