import com.google.gson.JsonObject;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class LiveDashboard extends JFrame {

    // =====================================================
    // DASHBOARD COMPONENTS
    // =====================================================

    private JLabel statusLabel;
    private JLabel packetRateLabel;
    private JLabel bytesLabel;
    private JLabel averageSizeLabel;
    private JLabel scoreLabel;
    private JLabel normalCountLabel;
    private JLabel suspiciousCountLabel;

    // New connection information
    private JLabel applicationLabel;
    private JLabel pidLabel;
    private JLabel destinationLabel;

    private JTextArea alertHistory;

    private JTable table;
    private DefaultTableModel tableModel;

    // Prevent duplicate table entries
    private String lastSignature = "";

    // Counters
    private int normalCount = 0;
    private int suspiciousCount = 0;

    // Client used to communicate with Python
    private final LiveStatusClient client =
            new LiveStatusClient();


    // =====================================================
    // CONSTRUCTOR
    // =====================================================

    public LiveDashboard() {

        setTitle(
                "IntelliGuard - Real-Time AI Intrusion Detection"
        );

        setSize(1400, 800);

        setDefaultCloseOperation(
                JFrame.EXIT_ON_CLOSE
        );

        setLocationRelativeTo(null);

        setLayout(
                new BorderLayout(15, 15)
        );


        // =================================================
        // MAIN PANEL
        // =================================================

        JPanel mainPanel =
                new JPanel(
                        new BorderLayout(15, 15)
                );

        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(
                        20, 20, 20, 20
                )
        );


        // =================================================
        // TITLE
        // =================================================

        JLabel title =
                new JLabel(
                        "INTELLIGUARD",
                        SwingConstants.CENTER
                );

        title.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        32
                )
        );


        JLabel subtitle =
                new JLabel(
                        "Real-Time AI Intrusion Detection System",
                        SwingConstants.CENTER
                );

        subtitle.setFont(
                new Font(
                        "Arial",
                        Font.PLAIN,
                        16
                )
        );


        JPanel titlePanel =
                new JPanel(
                        new GridLayout(2, 1, 0, 2)
                );

        titlePanel.add(title);
        titlePanel.add(subtitle);


        // =================================================
        // INFORMATION CARDS
        // =================================================

        JPanel infoPanel =
                new JPanel(
                        new GridLayout(
                                1,
                                6,
                                10,
                                10
                        )
                );


        packetRateLabel =
                createCard(
                        infoPanel,
                        "PACKET RATE"
                );


        bytesLabel =
                createCard(
                        infoPanel,
                        "BYTES / SEC"
                );


        averageSizeLabel =
                createCard(
                        infoPanel,
                        "AVERAGE PACKET"
                );


        scoreLabel =
                createCard(
                        infoPanel,
                        "AI SCORE"
                );


        normalCountLabel =
                createCard(
                        infoPanel,
                        "NORMAL"
                );


        suspiciousCountLabel =
                createCard(
                        infoPanel,
                        "SUSPICIOUS"
                );


        normalCountLabel.setText("0");
        suspiciousCountLabel.setText("0");


        // =================================================
        // AI STATUS
        // =================================================

        statusLabel =
                new JLabel(
                        "AI STATUS: CONNECTING...",
                        SwingConstants.CENTER
                );

        statusLabel.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        20
                )
        );

        statusLabel.setOpaque(true);

        statusLabel.setForeground(
                Color.BLACK
        );

        statusLabel.setBackground(
                new Color(
                        230,
                        230,
                        230
                )
        );

        statusLabel.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(
                                Color.DARK_GRAY,
                                1
                        ),
                        BorderFactory.createEmptyBorder(
                                10,
                                10,
                                10,
                                10
                        )
                )
        );


        // =================================================
        // CONNECTION INFORMATION
        // =================================================

        JPanel connectionPanel =
                new JPanel(
                        new GridLayout(1, 3, 10, 10)
                );

        connectionPanel.setBorder(
                BorderFactory.createTitledBorder(
                        "CURRENT CONNECTION ATTRIBUTION"
                )
        );


        applicationLabel =
                createConnectionLabel(
                        connectionPanel,
                        "APPLICATION"
                );


        pidLabel =
                createConnectionLabel(
                        connectionPanel,
                        "PID"
                );


        destinationLabel =
                createConnectionLabel(
                        connectionPanel,
                        "DESTINATION"
                );


        // =================================================
        // HEADER PANEL
        // =================================================

        JPanel headerPanel =
                new JPanel(
                        new BorderLayout(
                                10,
                                10
                        )
                );


        headerPanel.add(
                titlePanel,
                BorderLayout.NORTH
        );


        headerPanel.add(
                infoPanel,
                BorderLayout.CENTER
        );


        JPanel statusAndConnection =
                new JPanel(
                        new BorderLayout(10, 10)
                );

        statusAndConnection.add(
                statusLabel,
                BorderLayout.NORTH
        );

        statusAndConnection.add(
                connectionPanel,
                BorderLayout.CENTER
        );


        headerPanel.add(
                statusAndConnection,
                BorderLayout.SOUTH
        );


        mainPanel.add(
                headerPanel,
                BorderLayout.NORTH
        );


        // =================================================
        // LIVE TRAFFIC TABLE
        // =================================================

        String[] columns = {

                "Packet Rate",
                "Bytes/sec",
                "Average Size",
                "TCP Ratio",
                "UDP Ratio",
                "Sources",
                "Destinations",
                "Ports",
                "Application",
                "Destination",
                "AI Status"
        };


        tableModel =
                new DefaultTableModel(
                        columns,
                        0
                ) {

                    @Override
                    public boolean isCellEditable(
                            int row,
                            int column
                    ) {

                        return false;
                    }
                };


        table =
                new JTable(
                        tableModel
                );


        table.setRowHeight(28);


        table.setFont(
                new Font(
                        "Arial",
                        Font.PLAIN,
                        12
                )
        );


        table.getTableHeader().setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        12
                )
        );


        JScrollPane scrollPane =
                new JScrollPane(
                        table
                );


        mainPanel.add(
                scrollPane,
                BorderLayout.CENTER
        );


        // =================================================
        // LIVE ALERT HISTORY
        // =================================================

        alertHistory =
                new JTextArea();

        alertHistory.setEditable(
                false
        );


        alertHistory.setFont(
                new Font(
                        "Monospaced",
                        Font.PLAIN,
                        12
                )
        );


        alertHistory.setText(
                "No suspicious activity detected yet."
        );


        alertHistory.setLineWrap(
                true
        );


        alertHistory.setWrapStyleWord(
                true
        );


        alertHistory.setBorder(
                BorderFactory.createTitledBorder(
                        "LIVE ALERT HISTORY"
                )
        );


        JScrollPane alertScrollPane =
                new JScrollPane(
                        alertHistory
                );


        alertScrollPane.setPreferredSize(
                new Dimension(
                        380,
                        0
                )
        );


        mainPanel.add(
                alertScrollPane,
                BorderLayout.EAST
        );


        // =================================================
        // FOOTER
        // =================================================

        JLabel footer =
                new JLabel(
                        "REAL NETWORK TRAFFIC • AI ANOMALY DETECTION • PROCESS ATTRIBUTION • LIVE",
                        SwingConstants.CENTER
                );


        footer.setFont(
                new Font(
                        "Arial",
                        Font.PLAIN,
                        13
                )
        );


        mainPanel.add(
                footer,
                BorderLayout.SOUTH
        );


        setContentPane(
                mainPanel
        );


        // =================================================
        // LIVE UPDATE TIMER
        // =================================================

        Timer timer =
                new Timer(
                        3000,
                        e -> fetchLiveData()
                );


        timer.start();


        // First update immediately
        fetchLiveData();
    }


    // =====================================================
    // CREATE CARD
    // =====================================================

    private JLabel createCard(
            JPanel panel,
            String title
    ) {

        JPanel card =
                new JPanel(
                        new BorderLayout()
                );


        card.setBorder(
                BorderFactory.createTitledBorder(
                        title
                )
        );


        JLabel value =
                new JLabel(
                        "--",
                        SwingConstants.CENTER
                );


        value.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        19
                )
        );


        card.add(
                value,
                BorderLayout.CENTER
        );


        panel.add(card);


        return value;
    }


    // =====================================================
    // CREATE CONNECTION LABEL
    // =====================================================

    private JLabel createConnectionLabel(
            JPanel panel,
            String title
    ) {

        JPanel card =
                new JPanel(
                        new BorderLayout()
                );


        card.setBorder(
                BorderFactory.createTitledBorder(
                        title
                )
        );


        JLabel value =
                new JLabel(
                        "Unknown",
                        SwingConstants.CENTER
                );


        value.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        15
                )
        );


        card.add(
                value,
                BorderLayout.CENTER
        );


        panel.add(card);


        return value;
    }


    // =====================================================
    // GET LIVE DATA FROM PYTHON
    // =====================================================

    private void fetchLiveData() {

        new SwingWorker<JsonObject, Void>() {

            @Override
            protected JsonObject doInBackground()
                    throws Exception {

                return client.getLiveStatus();
            }


            @Override
            protected void done() {

                try {

                    JsonObject data =
                            get();

                    updateDashboard(
                            data
                    );

                } catch (Exception e) {

                    statusLabel.setText(
                            "AI STATUS: CONNECTION ERROR"
                    );

                    statusLabel.setForeground(
                            Color.WHITE
                    );

                    statusLabel.setBackground(
                            Color.DARK_GRAY
                    );
                }
            }

        }.execute();
    }


    // =====================================================
    // UPDATE DASHBOARD
    // =====================================================

    private void updateDashboard(
            JsonObject data
    ) {

        String status =
                data.get(
                        "status"
                ).getAsString();


        double packetRate =
                data.get(
                        "packet_rate"
                ).getAsDouble();


        double bytesPerSec =
                data.get(
                        "bytes_per_sec"
                ).getAsDouble();


        double averagePacket =
                data.get(
                        "average_packet_size"
                ).getAsDouble();


        double tcpRatio =
                data.get(
                        "tcp_ratio"
                ).getAsDouble();


        double udpRatio =
                data.get(
                        "udp_ratio"
                ).getAsDouble();


        int sources =
                data.get(
                        "unique_sources"
                ).getAsInt();


        int destinations =
                data.get(
                        "unique_destinations"
                ).getAsInt();


        int ports =
                data.get(
                        "unique_ports"
                ).getAsInt();


        double score =
                data.get(
                        "anomaly_score"
                ).getAsDouble();


        // =================================================
        // NEW CONNECTION DATA
        // =================================================

        String application =
                data.has("application")
                        ? data.get("application").getAsString()
                        : "Unknown";


        int pid =
                data.has("pid")
                        ? data.get("pid").getAsInt()
                        : 0;


        String destinationIp =
                data.has("destination_ip")
                        ? data.get("destination_ip").getAsString()
                        : "Unknown";


        int destinationPort =
                data.has("destination_port")
                        ? data.get("destination_port").getAsInt()
                        : 0;


        String destination;

        if (
                destinationIp.equals("Unknown")
                        || destinationPort == 0
        ) {

            destination = "Unknown";

        } else {

            destination =
                    destinationIp
                            + ":"
                            + destinationPort;
        }


        // =================================================
        // UPDATE CARDS
        // =================================================

        packetRateLabel.setText(
                String.format(
                        "%.2f / sec",
                        packetRate
                )
        );


        bytesLabel.setText(
                String.format(
                        "%.2f",
                        bytesPerSec
                )
        );


        averageSizeLabel.setText(
                String.format(
                        "%.2f bytes",
                        averagePacket
                )
        );


        scoreLabel.setText(
                String.format(
                        "%.4f",
                        score
                )
        );


        // =================================================
        // UPDATE CONNECTION PANEL
        // =================================================

        applicationLabel.setText(
                application
        );


        pidLabel.setText(
                String.valueOf(pid)
        );


        destinationLabel.setText(
                destination
        );


        // =================================================
        // UNIQUE RESULT CHECK
        // =================================================

        String signature =
                String.format(
                        "%.2f|%.2f|%.2f|%.3f|%.3f|%d|%d|%d|%s|%s|%s|%.4f",
                        packetRate,
                        bytesPerSec,
                        averagePacket,
                        tcpRatio,
                        udpRatio,
                        sources,
                        destinations,
                        ports,
                        application,
                        destination,
                        status,
                        score
                );


        if (
                !signature.equals(
                        lastSignature
                )
        ) {


            // =============================================
            // SUSPICIOUS
            // =============================================

            if (
                    "SUSPICIOUS".equalsIgnoreCase(
                            status
                    )
            ) {

                suspiciousCount++;


                suspiciousCountLabel.setText(
                        String.valueOf(
                                suspiciousCount
                        )
                );


                statusLabel.setText(
                        "🚨 SECURITY ALERT: SUSPICIOUS TRAFFIC DETECTED"
                );


                statusLabel.setForeground(
                        Color.WHITE
                );


                statusLabel.setBackground(
                        Color.RED
                );


                String alert =
                        String.format(
                                "[%tT] SUSPICIOUS | App: %s | PID: %d | Destination: %s | Rate: %.2f/sec | Score: %.4f%n",
                                new java.util.Date(),
                                application,
                                pid,
                                destination,
                                packetRate,
                                score
                        );


                // Remove initial message
                if (
                        alertHistory.getText().startsWith(
                                "No suspicious"
                        )
                ) {

                    alertHistory.setText(
                            ""
                    );
                }


                alertHistory.insert(
                        alert,
                        0
                );


            }

            // =============================================
            // NORMAL
            // =============================================

            else {

                normalCount++;


                normalCountLabel.setText(
                        String.valueOf(
                                normalCount
                        )
                );


                statusLabel.setText(
                        "✓ SYSTEM SECURE: NORMAL TRAFFIC DETECTED"
                );


                statusLabel.setForeground(
                        Color.BLACK
                );


                statusLabel.setBackground(
                        new Color(
                                220,
                                245,
                                220
                        )
                );
            }


            // =================================================
            // ADD TO TABLE
            // =================================================

            tableModel.insertRow(
                    0,
                    new Object[]{

                            String.format(
                                    "%.2f",
                                    packetRate
                            ),

                            String.format(
                                    "%.2f",
                                    bytesPerSec
                            ),

                            String.format(
                                    "%.2f",
                                    averagePacket
                            ),

                            String.format(
                                    "%.3f",
                                    tcpRatio
                            ),

                            String.format(
                                    "%.3f",
                                    udpRatio
                            ),

                            sources,

                            destinations,

                            ports,

                            application,

                            destination,

                            status
                    }
            );


            // Remember result
            lastSignature =
                    signature;
        }


        // =================================================
        // KEEP ONLY 20 TABLE ROWS
        // =================================================

        while (
                tableModel.getRowCount()
                        > 20
        ) {

            tableModel.removeRow(
                    tableModel.getRowCount() - 1
            );
        }


        // =================================================
        // KEEP ALERT HISTORY SMALL
        // =================================================

        String[] alerts =
                alertHistory.getText()
                        .split("\n");


        if (alerts.length > 20) {

            StringBuilder limited =
                    new StringBuilder();


            for (
                    int i = 0;
                    i < 20;
                    i++
            ) {

                limited.append(
                        alerts[i]
                );

                limited.append(
                        "\n"
                );
            }


            alertHistory.setText(
                    limited.toString()
            );
        }
    }


    // =====================================================
    // MAIN
    // =====================================================

    public static void main(
            String[] args
    ) {

        SwingUtilities.invokeLater(
                () -> {

                    LiveDashboard dashboard =
                            new LiveDashboard();

                    dashboard.setVisible(
                            true
                    );

                    dashboard.setAlwaysOnTop(
                            true
                    );

                    dashboard.toFront();

                    dashboard.requestFocus();
                }
        );
    }
}