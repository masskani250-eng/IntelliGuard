public class Request {

    private double requestRate;
    private double timeGapMs;
    private int failedLogins;
    private double packetSizeKb;
    private double payloadEntropy;

    public Request(double requestRate,
                   double timeGapMs,
                   int failedLogins,
                   double packetSizeKb,
                   double payloadEntropy) {

        this.requestRate = requestRate;
        this.timeGapMs = timeGapMs;
        this.failedLogins = failedLogins;
        this.packetSizeKb = packetSizeKb;
        this.payloadEntropy = payloadEntropy;
    }

    public double getRequestRate() {
        return requestRate;
    }

    public double getTimeGapMs() {
        return timeGapMs;
    }

    public int getFailedLogins() {
        return failedLogins;
    }

    public double getPacketSizeKb() {
        return packetSizeKb;
    }

    public double getPayloadEntropy() {
        return payloadEntropy;
    }
}