public class LiveStatusTest {

    public static void main(String[] args) {

        try {

            LiveStatusClient client = new LiveStatusClient();

            var result = client.getLiveStatus();

            System.out.println("===== INTELLIGUARD LIVE AI =====");
            System.out.println("Status       : " + result.get("status").getAsString());
            System.out.println("Packet Rate  : " + result.get("packet_rate").getAsDouble());
            System.out.println("Bytes/sec    : " + result.get("bytes_per_sec").getAsDouble());
            System.out.println("Average Size : " + result.get("average_packet_size").getAsDouble());
            System.out.println("AI Score     : " + result.get("anomaly_score").getAsDouble());
            System.out.println("================================");

        } catch (Exception e) {

            System.out.println("ERROR: Could not connect to Live AI service.");
            e.printStackTrace();
        }
    }
}