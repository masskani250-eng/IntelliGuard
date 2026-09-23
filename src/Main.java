import javax.swing.SwingUtilities;

public class Main {

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {

            LiveDashboard dashboard = new LiveDashboard();

            dashboard.setVisible(true);
            dashboard.setAlwaysOnTop(true);
            dashboard.toFront();
            dashboard.requestFocus();
        });
    }
}