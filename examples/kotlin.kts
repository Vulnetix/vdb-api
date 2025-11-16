// VDB API Testing - AWS SigV4 Authentication Example (Kotlin + AWS SDK for Java v2)
// Add to build.gradle.kts:
// implementation("software.amazon.awssdk:auth:2.20.0")
// implementation("software.amazon.awssdk:apache-client:2.20.0")
// implementation("com.google.code.gson:gson:2.10.1")
// implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider
import software.amazon.awssdk.auth.signer.Aws4Signer
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams
import software.amazon.awssdk.http.SdkHttpFullRequest
import software.amazon.awssdk.http.SdkHttpMethod
import software.amazon.awssdk.regions.Region
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest

// Step 1: Configuration - Set your Organization credentials
const val VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc" // Organization UUID (used as access key)
const val VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs" // Organization Secret (64 chars)
const val VVD_ACCESS_KEY = VVD_ORG // Access key is the Organization UUID
const val REGION = "us-east-1"
const val SERVICE = "vdb"
const val BASE_URL = "https://api.vdb.vulnetix.com/v1"

// Step 2: SHA-512 Hash utility function
fun sha512(data: String): String {
    val digest = MessageDigest.getInstance("SHA-512")
    val hashBytes = digest.digest(data.toByteArray())
    return hashBytes.joinToString("") { "%02x".format(it) }
}

// Step 3: Sign request using AWS SDK for Java v2
fun signRequest(
    method: SdkHttpMethod,
    uri: URI,
    path: String,
    body: String = ""
): SdkHttpFullRequest {
    // Create AWS credentials
    val credentials = AwsBasicCredentials.create(VVD_ACCESS_KEY, VVD_SECRET)
    val credentialsProvider = StaticCredentialsProvider.create(credentials)
    
    // Build the request
    val requestBuilder = SdkHttpFullRequest.builder()
        .method(method)
        .uri(uri)
        .encodedPath(path)
    
    if (body.isNotEmpty()) {
        requestBuilder.contentStreamProvider { body.byteInputStream() }
    }
    
    val request = requestBuilder.build()
    
    // Create signer parameters with SHA-512
    val signerParams = Aws4SignerParams.builder()
        .awsCredentials(credentials)
        .signingName(SERVICE)
        .signingRegion(Region.of(REGION))
        .build()
    
    // Sign the request using AWS4-HMAC-SHA512
    val signer = Aws4Signer.create()
    return signer.sign(request, signerParams)
}

// Step 4: JWT Token data class
data class JWTResponse(
    val token: String,
    val iss: String,
    val sub: String,
    val exp: Long
)

// Step 5: Get JWT token from /v1/auth/token
suspend fun getJWTToken(): String {
    val path = "/auth/token"
    val uri = URI.create("$BASE_URL$path")
    
    // Sign the request
    val signedRequest = signRequest(SdkHttpMethod.GET, uri, path)
    
    // Build HTTP request with signed headers
    val httpRequestBuilder = HttpRequest.newBuilder()
        .uri(uri)
        .GET()
    
    // Add all signed headers to the HTTP request
    signedRequest.headers().forEach { (name, values) ->
        values.forEach { value ->
            httpRequestBuilder.header(name, value)
        }
    }
    
    val httpRequest = httpRequestBuilder.build()
    
    // Make the request
    val client = HttpClient.newHttpClient()
    val response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString())
    
    // Parse JSON response
    val gson = Gson()
    val jwtResponse = gson.fromJson(response.body(), JWTResponse::class.java)
    
    println("JWT token obtained (expires in 15 minutes): ${jwtResponse.token.take(50)}...")
    println("Token details:")
    println("  Issuer: ${jwtResponse.iss}")
    println("  Subject: ${jwtResponse.sub}")
    println("  Expires: ${java.time.Instant.ofEpochSecond(jwtResponse.exp)}")
    
    return jwtResponse.token
}

// Step 6: Make authenticated API request
suspend fun makeAPIRequest() {
    // Get JWT token
    val jwtToken = getJWTToken()
    
    // Make GET request to /ecosystems
    val apiPath = "/ecosystems"
    val apiUri = URI.create("$BASE_URL$apiPath")
    
    val httpRequest = HttpRequest.newBuilder()
        .uri(apiUri)
        .GET()
        .header("Authorization", "Bearer $jwtToken")
        .header("Content-Type", "application/json")
        .build()
    
    val client = HttpClient.newHttpClient()
    val response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString())
    
    // Parse and print response
    val gson = Gson()
    val jsonResponse = gson.fromJson(response.body(), JsonObject::class.java)
    println("API Response:")
    println(gson.toJson(jsonResponse))
}

// Step 7: Main function to execute the request
suspend fun main() {
    try {
        makeAPIRequest()
    } catch (e: Exception) {
        println("Error: ${e.message}")
        e.printStackTrace()
    }
}
