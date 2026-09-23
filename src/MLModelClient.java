import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class MLModelClient {

    private final HttpClient client;
    private final Gson gson;

    public MLModelClient() {
        client = HttpClient.newHttpClient();
        gson = new Gson();
    }

    public MLResponse predict(Request request) throws Exception {

        String json = gson.toJson(request);

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:5000/predict"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpResponse<String> response = client.send(
                httpRequest,
                HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new RuntimeException(
                    "Prediction failed. HTTP status: "
                            + response.statusCode()
            );
        }

        return gson.fromJson(
                response.body(),
                MLResponse.class
        );
    }

    // Send human feedback to the adaptive-learning API
    public String sendFeedback(
            Request request,
            String label
    ) throws Exception {

        JsonObject json = new JsonObject();

        json.addProperty(
                "request_rate",
                request.getRequestRate()
        );

        json.addProperty(
                "time_gap_ms",
                request.getTimeGapMs()
        );

        json.addProperty(
                "failed_logins",
                request.getFailedLogins()
        );

        json.addProperty(
                "packet_size_kb",
                request.getPacketSizeKb()
        );

        json.addProperty(
                "payload_entropy",
                request.getPayloadEntropy()
        );

        json.addProperty(
                "label",
                label
        );

        HttpRequest httpRequest =
                HttpRequest.newBuilder()
                        .uri(URI.create(
                                "http://127.0.0.1:5000/feedback"
                        ))
                        .header(
                                "Content-Type",
                                "application/json"
                        )
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        gson.toJson(json)
                                )
                        )
                        .build();

        HttpResponse<String> response =
                client.send(
                        httpRequest,
                        HttpResponse.BodyHandlers.ofString()
                );

        if (response.statusCode() != 200) {
            throw new RuntimeException(
                    "Feedback failed. HTTP status: "
                            + response.statusCode()
            );
        }

        return response.body();
    }
}