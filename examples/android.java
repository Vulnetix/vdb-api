// VDB API Testing - AWS SigV4 Authentication Example (Android/Java)
// This example uses the AWS SDK for Android with AWS SigV4 signing
//
// Add to your build.gradle (app level):
// dependencies {
//     implementation "com.amazonaws:aws-android-sdk-core:2.77.+"
//     implementation "com.squareup.okhttp3:okhttp:4.12.0"
//     implementation "com.google.code.gson:gson:2.10.1"
// }

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.http.HttpMethodName;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.Map;

public class VDBAPIClient {
    
    // Step 1: Configuration - Set your Organization credentials
    private static final String VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc"; // Organization UUID (access key)
    private static final String VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs"; // Organization Secret (64 chars)
    private static final String VVD_ACCESS_KEY = VVD_ORG; // Access key is the Organization UUID
    
    private static final String BASE_URL = "https://api.vdb.vulnetix.com/v1";
    private static final String REGION = "us-east-1";
    private static final String SERVICE_NAME = "vdb";
    
    private final OkHttpClient httpClient;
    private final Gson gson;
    private String jwtToken;
    
    public VDBAPIClient() {
        this.httpClient = new OkHttpClient();
        this.gson = new Gson();
    }
    
    // Step 2: Sign request using AWS SigV4
    private Map<String, String> signRequest(String method, String path, String content) {
        try {
            // Create AWS credentials
            AWSCredentials credentials = new BasicAWSCredentials(VVD_ACCESS_KEY, VVD_SECRET);
            
            // Create a request object
            DefaultRequest<?> request = new DefaultRequest<>(SERVICE_NAME);
            request.setHttpMethod(HttpMethodName.valueOf(method));
            request.setEndpoint(URI.create(BASE_URL));
            request.setResourcePath(path);
            
            // Add content if present
            if (content != null && !content.isEmpty()) {
                request.setContent(new ByteArrayInputStream(content.getBytes("UTF-8")));
            }
            
            // Sign the request
            AWS4Signer signer = new AWS4Signer();
            signer.setRegionName(REGION);
            signer.setServiceName(SERVICE_NAME);
            signer.sign(request, credentials);
            
            return request.getHeaders();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign request", e);
        }
    }
    
    // Step 3: Get JWT token from /v1/auth/token
    public String getJWTToken() throws Exception {
        String path = "/auth/token";
        String url = BASE_URL + path;
        
        // Sign the request
        Map<String, String> signedHeaders = signRequest("GET", path, "");
        
        // Build the HTTP request
        Request.Builder requestBuilder = new Request.Builder().url(url);
        
        // Add signed headers
        for (Map.Entry<String, String> entry : signedHeaders.entrySet()) {
            requestBuilder.addHeader(entry.getKey(), entry.getValue());
        }
        
        Request request = requestBuilder.build();
        
        // Execute the request
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new Exception("Failed to obtain JWT token: " + response.code());
            }
            
            String responseBody = response.body().string();
            JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
            
            if (!jsonResponse.has("token")) {
                throw new Exception("No token in response");
            }
            
            this.jwtToken = jsonResponse.get("token").getAsString();
            
            System.out.println("JWT token obtained (expires in 15 minutes): " +
                this.jwtToken.substring(0, Math.min(50, this.jwtToken.length())) + "...");
            System.out.println("Token issuer: " + jsonResponse.get("iss").getAsString());
            System.out.println("Token subject: " + jsonResponse.get("sub").getAsString());
            System.out.println("Token expiry: " + jsonResponse.get("exp").getAsLong());
            
            return this.jwtToken;
        }
    }
    
    // Step 4: Make authenticated API request
    public JsonObject makeAPIRequest() throws Exception {
        // Get JWT token if not already obtained
        if (this.jwtToken == null) {
            getJWTToken();
        }
        
        String path = "/ecosystems";
        String url = BASE_URL + path;
        
        System.out.println("Making GET request to " + path + "...");
        
        // Build the HTTP request with JWT Bearer token
        Request request = new Request.Builder()
            .url(url)
            .get()
            .addHeader("Authorization", "Bearer " + this.jwtToken)
            .addHeader("Content-Type", "application/json")
            .build();
        
        // Execute the request
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new Exception("API request failed: " + response.code());
            }
            
            String responseBody = response.body().string();
            JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
            
            System.out.println("API Response: " + gson.toJson(jsonResponse));
            
            return jsonResponse;
        }
    }
    
    // Main method for testing
    public static void main(String[] args) {
        try {
            VDBAPIClient client = new VDBAPIClient();
            
            // Get JWT token
            client.getJWTToken();
            
            // Make API request
            JsonObject result = client.makeAPIRequest();
            
            System.out.println("Request completed successfully!");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

// Usage in Android Activity or Fragment:
//
// ExecutorService executor = Executors.newSingleThreadExecutor();
// executor.execute(() -> {
//     try {
//         VDBAPIClient client = new VDBAPIClient();
//         client.getJWTToken();
//         JsonObject result = client.makeAPIRequest();
//
//         // Update UI on main thread
//         runOnUiThread(() -> {
//             // Handle response
//         });
//     } catch (Exception e) {
//         e.printStackTrace();
//     }
// });
