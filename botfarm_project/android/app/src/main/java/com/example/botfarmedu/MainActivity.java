package com.example.botfarmedu;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.util.Log;

import com.example.botfarmedu.network.ApiClient;
import com.example.botfarmedu.services.BotService;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "BotFarm";
    private BotService botService;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Iniciar el servicio del bot
        botService = new BotService(this);
        botService.startService();
        
        // Registrar este dispositivo en el servidor central
        registerDevice();
    }
    
    private void registerDevice() {
        String deviceId = android.provider.Settings.Secure.getString(
            getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        
        ApiClient.getInstance().registerDevice(deviceId, 
            response -> Log.d(TAG, "Device registered successfully: " + deviceId),
            error -> Log.e(TAG, "Failed to register device: " + error.getMessage())
        );
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (botService != null) {
            botService.stopService();
        }
    }
}
