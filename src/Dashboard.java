import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class Dashboard extends JFrame {

    private JLabel totalLabel;
    private JLabel normalLabel;
    private JLabel attackLabel;
    private JLabel attackRateLabel;
    private JLabel statusLabel;

    private DefaultTableModel tableModel;
    private JTable table;
    private JPanel chartPanel;

    // Keep the Request associated with each table row
    private final List<Request> requests = new ArrayList<>();

    private int totalRequests = 0;
    private int normalRequests = 0;
    private int attackRequests = 0;

    public Dashboard() {

        setTitle("IntelliGuard - AI Intrusion Detection");
        setSize(1200, 800);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(12, 12));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(15, 15, 15, 15)
        );

        // =========================
        // TITLE
        // =========================

        JLabel title = new JLabel(
                "INTELLIGUARD",
                SwingConstants.CENTER
        );
        title.setFont(new Font("Arial", Font.BOLD, 30));

        JLabel subtitle = new JLabel(
                "AI-Powered Adaptive Intrusion Detection System",
                SwingConstants.CENTER
        );
        subtitle.setFont(new Font("Arial", Font.PLAIN, 16));

        JPanel titlePanel = new JPanel(
                new GridLayout(2, 1, 0, 2)
        );

        titlePanel.add(title);
        titlePanel.add(subtitle);

        // =========================
        // STATISTICS
        // =========================

        JPanel statsPanel = new JPanel(
                new GridLayout(1, 4, 12, 0)
        );

        totalLabel = createStatLabel("TOTAL\n0");
        normalLabel = createStatLabel("NORMAL\n0");
        attackLabel = createStatLabel("ATTACK\n0");
        attackRateLabel = createStatLabel("ATTACK RATE\n0%");

        statsPanel.add(totalLabel);
        statsPanel.add(normalLabel);
        statsPanel.add(attackLabel);
        statsPanel.add(attackRateLabel);

        // =========================
        // STATUS
        // =========================

        statusLabel = new JLabel(
                "SYSTEM STATUS: Monitoring...",
                SwingConstants.CENTER
        );

        statusLabel.setFont(
                new Font("Arial", Font.BOLD, 16)
        );

        // =========================
        // HEADER
        // =========================

        JPanel headerPanel = new JPanel(
                new BorderLayout(10, 10)
        );

        headerPanel.add(titlePanel, BorderLayout.NORTH);
        headerPanel.add(statsPanel, BorderLayout.CENTER);
        headerPanel.add(statusLabel, BorderLayout.SOUTH);

        mainPanel.add(
                headerPanel,
                BorderLayout.NORTH
        );

        // =========================
        // TABLE
        // =========================

        String[] columns = {
                "Request Rate",
                "Time Gap",
                "Failed Logins",
                "Packet Size",
                "Entropy",
                "Prediction",
                "Confidence"
        };

        tableModel = new DefaultTableModel(
                columns,
                0
        );

        table = new JTable(tableModel);

        table.setRowHeight(28);
        table.setFont(
                new Font("Arial", Font.PLAIN, 13)
        );

        table.getTableHeader().setFont(
                new Font("Arial", Font.BOLD, 14)
        );

        // Highlight Attack rows
        table.setDefaultRenderer(
                Object.class,
                new DefaultTableCellRenderer() {

                    @Override
                    public Component getTableCellRendererComponent(
                            JTable table,
                            Object value,
                            boolean isSelected,
                            boolean hasFocus,
                            int row,
                            int column
                    ) {

                        Component component =
                                super.getTableCellRendererComponent(
                                        table,
                                        value,
                                        isSelected,
                                        hasFocus,
                                        row,
                                        column
                                );

                        Object prediction =
                                table.getValueAt(row, 5);

                        if ("Attack".equals(prediction)) {
                            component.setBackground(
                                    new Color(255, 205, 205)
                            );
                        } else {
                            component.setBackground(
                                    Color.WHITE
                            );
                        }

                        return component;
                    }
                }
        );

        JScrollPane scrollPane =
                new JScrollPane(table);

        // =========================
        // FEEDBACK BUTTONS
        // =========================

        JButton normalButton =
                new JButton("Mark Selected as NORMAL");

        JButton attackButton =
                new JButton("Mark Selected as ATTACK");

        normalButton.addActionListener(e ->
                sendSelectedFeedback("Normal")
        );

        attackButton.addActionListener(e ->
                sendSelectedFeedback("Attack")
        );

        JPanel buttonPanel = new JPanel(
                new FlowLayout(
                        FlowLayout.CENTER,
                        15,
                        8
                )
        );

        buttonPanel.add(normalButton);
        buttonPanel.add(attackButton);

        // =========================
        // GRAPH
        // =========================

        chartPanel = new JPanel() {

            @Override
            protected void paintComponent(Graphics g) {

                super.paintComponent(g);

                int width = getWidth();

                int total =
                        normalRequests + attackRequests;

                int normalHeight = 0;
                int attackHeight = 0;

                if (total > 0) {

                    normalHeight =
                            (int) (
                                    (normalRequests /
                                            (double) total)
                                            * 100
                            );

                    attackHeight =
                            (int) (
                                    (attackRequests /
                                            (double) total)
                                            * 100
                            );
                }

                g.setFont(
                        new Font(
                                "Arial",
                                Font.BOLD,
                                16
                        )
                );

                g.drawString(
                        "TRAFFIC SUMMARY",
                        20,
                        25
                );

                int baseY = 125;

                int normalX =
                        width / 2 - 110;

                int attackX =
                        width / 2 + 30;

                g.fillRect(
                        normalX,
                        baseY - normalHeight,
                        80,
                        normalHeight
                );

                g.fillRect(
                        attackX,
                        baseY - attackHeight,
                        80,
                        attackHeight
                );

                g.drawString(
                        "Normal: " + normalRequests,
                        normalX - 15,
                        baseY + 30
                );

                g.drawString(
                        "Attack: " + attackRequests,
                        attackX - 10,
                        baseY + 30
                );
            }
        };

        chartPanel.setPreferredSize(
                new Dimension(500, 160)
        );

        // =========================
        // CONTENT
        // =========================

        JPanel centerPanel = new JPanel(
                new BorderLayout(10, 10)
        );

        centerPanel.add(
                chartPanel,
                BorderLayout.NORTH
        );

        centerPanel.add(
                scrollPane,
                BorderLayout.CENTER
        );

        centerPanel.add(
                buttonPanel,
                BorderLayout.SOUTH
        );

        mainPanel.add(
                centerPanel,
                BorderLayout.CENTER
        );

        setContentPane(mainPanel);
    }

    // =========================
    // STAT LABEL
    // =========================

    private JLabel createStatLabel(String text) {

        JLabel label = new JLabel(
                "",
                SwingConstants.CENTER
        );

        label.setFont(
                new Font("Arial", Font.BOLD, 18)
        );

        label.setBorder(
                BorderFactory.createLineBorder(
                        Color.GRAY
                )
        );

        setStatText(label, text);

        return label;
    }

    private void setStatText(
            JLabel label,
            String text
    ) {

        label.setText(
                "<html><center>"
                        + text.replace(
                        "\n",
                        "<br>"
                )
                        + "</center></html>"
        );
    }

    // =========================
    // ADD LIVE RESULT
    // =========================

    public void addResult(
            Request request,
            MLResponse response
    ) {

        totalRequests++;

        String prediction =
                response.getPrediction();

        if (prediction.equalsIgnoreCase("Attack")) {

            attackRequests++;
            statusLabel.setText(
                    "🚨 SECURITY ALERT — ATTACK DETECTED | Confidence: "
                            + String.format(
                            "%.2f",
                            response.getConfidence()
                    )
                            + "%"
            );

        } else {

            normalRequests++;

            statusLabel.setText(
                    "SYSTEM STATUS: Normal traffic detected"
            );
        }

        // Store request for feedback
        requests.add(request);

        // Add table row
        tableModel.addRow(
                new Object[]{
                        String.format(
                                "%.2f",
                                request.getRequestRate()
                        ),

                        String.format(
                                "%.2f ms",
                                request.getTimeGapMs()
                        ),

                        request.getFailedLogins(),

                        String.format(
                                "%.2f KB",
                                request.getPacketSizeKb()
                        ),

                        String.format(
                                "%.2f",
                                request.getPayloadEntropy()
                        ),

                        prediction,

                        String.format(
                                "%.2f%%",
                                response.getConfidence()
                        )
                }
        );

        // Keep only latest 100 rows
        if (tableModel.getRowCount() > 100) {

            tableModel.removeRow(0);
            requests.remove(0);
        }

        double attackRate =
                (attackRequests /
                        (double) totalRequests)
                        * 100;

        setStatText(
                totalLabel,
                "TOTAL\n" + totalRequests
        );

        setStatText(
                normalLabel,
                "NORMAL\n" + normalRequests
        );

        setStatText(
                attackLabel,
                "ATTACK\n" + attackRequests
        );

        setStatText(
                attackRateLabel,
                "ATTACK RATE\n"
                        + String.format(
                        "%.1f%%",
                        attackRate
                )
        );

        chartPanel.repaint();
    }

    // =========================
    // SEND FEEDBACK
    // =========================

    private void sendSelectedFeedback(
            String label
    ) {

        int selectedRow =
                table.getSelectedRow();

        if (selectedRow == -1) {

            JOptionPane.showMessageDialog(
                    this,
                    "Please select a traffic row first.",
                    "No Row Selected",
                    JOptionPane.WARNING_MESSAGE
            );

            return;
        }

        if (selectedRow >= requests.size()) {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to find the selected request.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );

            return;
        }

        Request selectedRequest =
                requests.get(selectedRow);

        try {

            MLModelClient client =
                    new MLModelClient();

            String result =
                    client.sendFeedback(
                            selectedRequest,
                            label
                    );

            statusLabel.setText(
                    "MODEL UPDATED | Feedback: "
                            + label
            );

            JOptionPane.showMessageDialog(
                    this,
                    "Feedback sent successfully!\n\n"
                            + "Label: " + label
                            + "\n\n"
                            + "The Random Forest model has been retrained.",
                    "Adaptive Learning",
                    JOptionPane.INFORMATION_MESSAGE
            );

        } catch (Exception ex) {

            JOptionPane.showMessageDialog(
                    this,
                    "Could not send feedback.\n\n"
                            + ex.getMessage(),
                    "Feedback Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }
}