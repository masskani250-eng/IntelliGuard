public class MLResponse {

    private String prediction;
    private double confidence;

    public MLResponse(String prediction, double confidence) {
        this.prediction = prediction;
        this.confidence = confidence;
    }

    public String getPrediction() {
        return prediction;
    }

    public double getConfidence() {
        return confidence;
    }
}
