import java.util.Random;

public class TrafficGenerator {

    private final Random random = new Random();

    public Request generateRequest() {

        // 30% chance of generating attack traffic
        boolean attack = random.nextDouble() < 0.30;

        if (attack) {

            double requestRate =
                    8 + random.nextDouble() * 17;

            double timeGap =
                    20 + random.nextDouble() * 130;

            int failedLogins =
                    4 + random.nextInt(12);

            double packetSize =
                    0.1 + random.nextDouble() * 1.4;

            double entropy =
                    6 + random.nextDouble() * 3;

            return new Request(
                    requestRate,
                    timeGap,
                    failedLogins,
                    packetSize,
                    entropy
            );

        } else {

            double requestRate =
                    0.5 + random.nextDouble() * 4.5;

            double timeGap =
                    200 + random.nextDouble() * 1000;

            int failedLogins =
                    random.nextInt(3);

            double packetSize =
                    1 + random.nextDouble() * 9;

            double entropy =
                    2 + random.nextDouble() * 3;

            return new Request(
                    requestRate,
                    timeGap,
                    failedLogins,
                    packetSize,
                    entropy
            );
        }
    }
}