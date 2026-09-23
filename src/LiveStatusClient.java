import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class LiveStatusClient {

    private final HttpClient client;

    public LiveStatusClient() {
        client = HttpClient.newHttpClient();
    }

    public JsonObject getLiveStatus() throws Exception {

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:5000/status"))
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                );

        return JsonParser.parseString(response.body())
                .getAsJsonObject();
    }
}