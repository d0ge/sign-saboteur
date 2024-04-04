package one.d4d.signsaboteur.utils;

import java.lang.reflect.Type;
import java.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class GsonHelper {
    public static final Gson customGson = new GsonBuilder()
            .excludeFieldsWithoutExposeAnnotation()
            .registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
            .create();

    private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
        public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            return Base64.getUrlDecoder().decode(json.getAsString());
        }

        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base64.getUrlEncoder().encodeToString(src));
        }
    }
}
