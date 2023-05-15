package cl.gob.digital.firma.firmaJson;

import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@SpringBootApplication
public class FirmaJsonApplication {
	//Variables de ambiente a configurar, ver archivo readme.
	public static final String ENTITY =System.getenv( "ENTITY");
	public static final String API_TOKEN_KEY = System.getenv( "API_TOKEN_KEY");
	public static final String RUN = System.getenv( "RUN");
	public static final String PURPOSE = System.getenv( "PURPOSE");
	public static final String SECRET_KEY = System.getenv( "SECRET_KEY");
	public static final String ENDPOINT_API = System.getenv( "ENDPOINT_API");

	//Ruta local del archivo a firmar
	public static final String JSON_PATH = "/Users/sfuentealba/Downloads/ejemplo.json";

	public static void main(String[] args) {
		SpringApplication.run(FirmaJsonApplication.class, args);
		try {
			// crear un nuevo archivo igual al original y guardarlo
			Path originalPath = Paths.get(JSON_PATH);
			Path parentDirectoryPath = originalPath.getParent();
			String originalFileName = originalPath.getFileName().toString();
			String currentDateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
			String newFileName = currentDateTime + "-" + originalFileName;
			Path newFilePath = parentDirectoryPath.resolve(newFileName);

			if (Files.exists(newFilePath)) {
				throw new IOException("El archivo ya existe: " + newFilePath);
			}

			Files.copy(originalPath, newFilePath);

			try {

				// obtener base64 del archivo
				byte[] json = Files.readAllBytes(Paths.get(newFilePath.toUri()));
				String base64 = Base64.getEncoder().encodeToString(json);

				// obtener SHA-256 del archivo para checksum
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] encodedhash = digest.digest(base64.getBytes(StandardCharsets.UTF_8));
				String checkSum = Base64.getEncoder().encodeToString(encodedhash);

				// llamar al endpoint para firmar el documento y obtener la respuesta
				String contentResponse = callEndpointToSign(base64, originalFileName, checkSum);

				// decodificar el documento firmado
				Base64.Decoder decoder = Base64.getDecoder();
				String jws = new String(decoder.decode(contentResponse));
				Gson gson = new Gson();
				Jws jwsO = gson.fromJson(jws, Jws.class);
				// escribir el archivo firmado en la ruta JSON_PATH_END
				String JSON_PATH_END = newFilePath.toString().replace(".json", "-firmado.json");
				FileOutputStream fos = new FileOutputStream(JSON_PATH_END);
				fos.write(jwsO.getJws().getBytes(StandardCharsets.UTF_8));
				fos.close();

				System.out.println("El documento se genero exitosamente en: " + JSON_PATH_END);

			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (
				Exception e) {
			e.printStackTrace();
		}
	}

	public static String callEndpointToSign(String jsonBase64, String fileName, String checksumSha256) throws IOException {
		System.out.println("Inicio de llamada al endpoint de FirmaGob");

		// Crear el jwt para el parametro token
		String token = createJWT();

		//generando body para la peticion POST
		Map<String, Object> requestBody = new HashMap<>();
		requestBody.put("token", token);
		requestBody.put("api_token_key", API_TOKEN_KEY);

		// cargar informacion de archivo:se debera agregar uno por cada archivo que se envia a firma
		Map<String, Object> archivo1 = new HashMap<>();
		archivo1.put("content-type", "application/json");
		archivo1.put("description", fileName);
		archivo1.put("checksum", checksumSha256);
		archivo1.put("content", jsonBase64);

		// crear lista de archivos
		List<Map<String, Object>> archivos = new ArrayList<>();

		archivos.add(archivo1);

		// setear lista de archivos al requestBody
		requestBody.put("files", archivos);

		Gson gson = new Gson();
		String jsonBody = gson.toJson(requestBody);

		URL urlObj = new URL(ENDPOINT_API);
		HttpURLConnection con = (HttpURLConnection) urlObj.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-Type", "application/json");
		con.setDoOutput(true);

		OutputStream os = con.getOutputStream();
		byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);

		os.write(input, 0, input.length);
		int statusCode = con.getResponseCode();

		// Leer la respuesta
		System.out.println("Leyendo respuesta del endpoint");
		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuilder response = new StringBuilder();
		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		if (statusCode == 200) {
			System.out.println("Llamada al endpoint exitosa, se retornara el content del archivo json firmado");

			Gson gsonResponse = new Gson();
			ResponseToJson jsonResponse = gsonResponse.fromJson(response.toString(), ResponseToJson.class);

			return jsonResponse.getFiles()[0].getContent();
		} else {
			System.out.println("Error al llamar al endpoint");
		}

		con.disconnect();
		return null;
	}

	public static String createJWT() {
		// Crear el JWT
		String token = null;
		// obteniendo fecha y hora actual agregando 5 minutos esto permite que la fecha del token siempre sea valida
		String expiration_date_time = LocalDateTime.now().plusMinutes(5).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
		try {
			String jwtToken = Jwts.builder()
					.claim("entity", ENTITY)
					.claim("run", RUN)
					.claim("expiration", expiration_date_time)
					.claim("purpose", PURPOSE)
					.setIssuedAt(new Date())
					.signWith(SignatureAlgorithm.HS256, SECRET_KEY.getBytes(StandardCharsets.UTF_8))
					.compact();

			System.out.println("Token generado: " + jwtToken);
			token = jwtToken;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return token;
	}

	/**
	 * Estructura de la respuesta envida por la API para. Se utilizo lombok a fin de simplificar el codigo
	 */
	@Getter
	@Setter
	static class ResponseToJson {
		private FileModel[] files;
		private Metadata metadata;
		private long idSolicitud;
	}

	@Getter
	@Setter
	static class Metadata {
		private boolean otpExpired;
		private int filesSigned;
		private int signedFailed;
		private int objectsReceived;

	}

	@Getter
	@Setter
	static class FileModel {
		private String content;
		private String status;
		private String description;
		private String contentType;
		private String documentStatus;
		private String checksum_original;
	}

	@Getter
	@Setter
	static class Jws {
		private String jws;
	}

}
