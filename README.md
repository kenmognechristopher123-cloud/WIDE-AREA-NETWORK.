Video LINK: https://claude.ai/public/artifacts/c8067ba7-5192-4365-bc33-e2c00adfea93


[Cloud Based Educational Platform..docx](https://github.com/user-attachments/files/24577110/Cloud.Based.Educational.Platform.docx)
[Cloud based educational platform code..txt](https://github.com/user-attachments/files/24577113/Cloud.based.educational.platform.code.txt)
/* 
 * NS-3 Simulation: Cloud-Based Educational Platform
 * 
 * This simulation models:
 * - Student clients accessing educational content
 * - Edge servers for content delivery
 * - Cloud data center for processing and storage
 * - Video streaming, file downloads, and interactive sessions
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("CloudEducationalPlatform");

// Custom application for educational traffic
class EducationalApp : public Application {
private:
    Ptr<Socket> m_socket;
    Address m_peer;
    uint32_t m_packetSize;
    uint32_t m_nPackets;
    DataRate m_dataRate;
    EventId m_sendEvent;
    bool m_running;
    uint32_t m_packetsSent;

    void StartApplication() {
        m_running = true;
        m_packetsSent = 0;
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(m_peer);
        SendPacket();
    }

    void StopApplication() {
        m_running = false;
        if (m_sendEvent.IsRunning()) {
            Simulator::Cancel(m_sendEvent);
        }
        if (m_socket) {
            m_socket->Close();
        }
    }

    void SendPacket() {
        Ptr<Packet> packet = Create<Packet>(m_packetSize);
        m_socket->Send(packet);
        m_packetsSent++;

        if (m_packetsSent < m_nPackets) {
            ScheduleNextTx();
        }
    }

    void ScheduleNextTx() {
        if (m_running) {
            Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));
            m_sendEvent = Simulator::Schedule(tNext, &EducationalApp::SendPacket, this);
        }
    }

public:
    EducationalApp() : m_socket(0), m_packetSize(1024), m_nPackets(1000), 
                       m_dataRate(DataRate("5Mbps")), m_running(false), m_packetsSent(0) {}

    void Setup(Address addr, uint32_t packetSize, uint32_t nPackets, DataRate dataRate) {
        m_peer = addr;
        m_packetSize = packetSize;
        m_nPackets = nPackets;
        m_dataRate = dataRate;
    }

    static TypeId GetTypeId() {
        static TypeId tid = TypeId("EducationalApp")
            .SetParent<Application>()
            .SetGroupName("Applications");
        return tid;
    }
};

int main(int argc, char *argv[]) {
    // Simulation parameters
    uint32_t nStudents = 50;
    uint32_t nEdgeServers = 3;
    double simTime = 30.0;
    bool enablePcap = false;
    bool verbose = true;

    CommandLine cmd;
    cmd.AddValue("nStudents", "Number of student clients", nStudents);
    cmd.AddValue("nEdge", "Number of edge servers", nEdgeServers);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("pcap", "Enable PCAP tracing", enablePcap);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    cmd.Parse(argc, argv);

    if (verbose) {
        LogComponentEnable("CloudEducationalPlatform", LOG_LEVEL_INFO);
    }

    NS_LOG_INFO("Creating Cloud Educational Platform with " << nStudents << " students");

    // Create nodes
    NodeContainer students;
    students.Create(nStudents);

    NodeContainer edgeServers;
    edgeServers.Create(nEdgeServers);

    NodeContainer cloudDataCenter;
    cloudDataCenter.Create(2); // Primary and backup servers

    NodeContainer gatewayRouter;
    gatewayRouter.Create(1);

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(students);
    internet.Install(edgeServers);
    internet.Install(cloudDataCenter);
    internet.Install(gatewayRouter);

    // Create point-to-point links
    PointToPointHelper p2pStudentToEdge;
    p2pStudentToEdge.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pStudentToEdge.SetChannelAttribute("Delay", StringValue("5ms"));

    PointToPointHelper p2pEdgeToGateway;
    p2pEdgeToGateway.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
    p2pEdgeToGateway.SetChannelAttribute("Delay", StringValue("10ms"));

    PointToPointHelper p2pGatewayToCloud;
    p2pGatewayToCloud.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
    p2pGatewayToCloud.SetChannelAttribute("Delay", StringValue("20ms"));

    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    std::vector<NetDeviceContainer> studentEdgeLinks;
    std::vector<Ipv4InterfaceContainer> studentEdgeInterfaces;

    // Connect students to edge servers (round-robin)
    for (uint32_t i = 0; i < nStudents; i++) {
        uint32_t edgeIndex = i % nEdgeServers;
        NodeContainer pair(students.Get(i), edgeServers.Get(edgeIndex));
        NetDeviceContainer link = p2pStudentToEdge.Install(pair);
        studentEdgeLinks.push_back(link);

        std::ostringstream subnet;
        subnet << "10.1." << (i + 1) << ".0";
        ipv4.SetBase(subnet.str().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer interfaces = ipv4.Assign(link);
        studentEdgeInterfaces.push_back(interfaces);
    }

    // Connect edge servers to gateway
    std::vector<Ipv4InterfaceContainer> edgeGatewayInterfaces;
    for (uint32_t i = 0; i < nEdgeServers; i++) {
        NodeContainer pair(edgeServers.Get(i), gatewayRouter.Get(0));
        NetDeviceContainer link = p2pEdgeToGateway.Install(pair);

        std::ostringstream subnet;
        subnet << "10.2." << (i + 1) << ".0";
        ipv4.SetBase(subnet.str().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer interfaces = ipv4.Assign(link);
        edgeGatewayInterfaces.push_back(interfaces);
    }

    // Connect gateway to cloud data center
    std::vector<Ipv4InterfaceContainer> cloudInterfaces;
    for (uint32_t i = 0; i < cloudDataCenter.GetN(); i++) {
        NodeContainer pair(gatewayRouter.Get(0), cloudDataCenter.Get(i));
        NetDeviceContainer link = p2pGatewayToCloud.Install(pair);

        std::ostringstream subnet;
        subnet << "10.3." << (i + 1) << ".0";
        ipv4.SetBase(subnet.str().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer interfaces = ipv4.Assign(link);
        cloudInterfaces.push_back(interfaces);
    }

    // Enable routing
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Install applications
    uint16_t port = 9;

    // Video streaming server on cloud
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps = echoServer.Install(cloudDataCenter.Get(0));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(simTime));

    // Student clients generating different types of traffic
    for (uint32_t i = 0; i < nStudents; i++) {
        UdpEchoClientHelper echoClient(cloudInterfaces[0].GetAddress(1), port);
        
        // Simulate different usage patterns
        if (i % 3 == 0) {
            // Video streaming - high bandwidth
            echoClient.SetAttribute("MaxPackets", UintegerValue(1000));
            echoClient.SetAttribute("Interval", TimeValue(Seconds(0.01)));
            echoClient.SetAttribute("PacketSize", UintegerValue(1400));
        } else if (i % 3 == 1) {
            // Interactive session - low latency
            echoClient.SetAttribute("MaxPackets", UintegerValue(500));
            echoClient.SetAttribute("Interval", TimeValue(Seconds(0.05)));
            echoClient.SetAttribute("PacketSize", UintegerValue(512));
        } else {
            // File download - bursty
            echoClient.SetAttribute("MaxPackets", UintegerValue(200));
            echoClient.SetAttribute("Interval", TimeValue(Seconds(0.1)));
            echoClient.SetAttribute("PacketSize", UintegerValue(1400));
        }

        ApplicationContainer clientApp = echoClient.Install(students.Get(i));
        double startTime = 2.0 + (i * 0.1); // Stagger start times
        clientApp.Start(Seconds(startTime));
        clientApp.Stop(Seconds(simTime - 1.0));
    }

    // Enable flow monitor for statistics
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    // Enable PCAP if requested
    if (enablePcap) {
        p2pGatewayToCloud.EnablePcapAll("cloud-edu-platform");
    }

    NS_LOG_INFO("Starting simulation for " << simTime << " seconds");
    
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // Print statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    std::cout << "\n=== Educational Platform Performance Statistics ===" << std::endl;
    std::cout << "Total Flows: " << stats.size() << std::endl;

    double totalThroughput = 0;
    double totalDelay = 0;
    uint32_t flowCount = 0;
    uint64_t totalPacketsSent = 0;
    uint64_t totalPacketsReceived = 0;

    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); 
         i != stats.end(); ++i) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        
        double flowThroughput = i->second.rxBytes * 8.0 / (simTime - 2.0) / 1000000.0;
        totalThroughput += flowThroughput;
        
        if (i->second.rxPackets > 0) {
            double avgDelay = i->second.delaySum.GetSeconds() / i->second.rxPackets * 1000;
            totalDelay += avgDelay;
            flowCount++;
        }
        
        totalPacketsSent += i->second.txPackets;
        totalPacketsReceived += i->second.rxPackets;
    }

    std::cout << "\nAggregate Statistics:" << std::endl;
    std::cout << "  Total Throughput: " << totalThroughput << " Mbps" << std::endl;
    std::cout << "  Average Delay: " << (flowCount > 0 ? totalDelay / flowCount : 0) << " ms" << std::endl;
    std::cout << "  Packets Sent: " << totalPacketsSent << std::endl;
    std::cout << "  Packets Received: " << totalPacketsReceived << std::endl;
    std::cout << "  Packet Delivery Ratio: " 
              << (totalPacketsSent > 0 ? (double)totalPacketsReceived / totalPacketsSent * 100 : 0) 
              << "%" << std::endl;

    Simulator::Destroy();
    
    NS_LOG_INFO("Simulation completed successfully");
    
    return 0;
}
