package com.example.botfarmedu.services;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.botfarmedu.MainActivity;
import com.example.botfarmedu.R;
import com.example.botfarmedu.network.ApiClient;
import com.example.botfarmedu.network.WebSocketClient;
import com.example.botfarmedu.tasks.TaskExecutor;
import com.example.botfarmedu.utils.PreferenceManager;

import java.util.Timer;
import java.util.TimerTask;

public class BotService extends Service {
    private static final String CHANNEL_ID = "BotServiceChannel";
    private static final int NOTIFICATION_ID = 1;
    private static final long HEARTBEAT_INTERVAL = 30000; // 30 segundos
    
    private WebSocketClient webSocketClient;
    private TaskExecutor taskExecutor;
    private Timer heartbeatTimer;
    private PreferenceManager prefManager;
    private String deviceId;
    
    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        
        prefManager = new PreferenceManager(this);
        deviceId = android.provider.Settings.Secure.getString(
            getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        
        // Inicializar el cliente WebSocket
        webSocketClient = new WebSocketClient(this);
        
        // Inicializar el ejecutor de tareas
        taskExecutor = new TaskExecutor(this);
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Crear una notificación para servicio en primer plano
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE);
        
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Bot Farm Service")
            .setContentText("El servicio está en ejecución")
            .setSmallIcon(R.drawable.ic_service)
            .setContentIntent(pendingIntent)
            .build();
        
        // Iniciar como servicio en primer plano
        startForeground(NOTIFICATION_ID, notification);
        
        // Conectar al WebSocket
        webSocketClient.connect();
        
        // Iniciar el temporizador de heartbeat
        startHeartbeatTimer();
        
        // Si el servicio se mata, reiniciarlo
        return START_STICKY;
    }
    
    private void startHeartbeatTimer() {
        heartbeatTimer = new Timer();
        heartbeatTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                sendHeartbeat();
            }
        }, 0, HEARTBEAT_INTERVAL);
    }
    
    private void sendHeartbeat() {
        // Implementación del método de heartbeat
    }
    
    // Resto del código...
    
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
    
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(
                CHANNEL_ID,
                "Bot Service Channel",
                NotificationManager.IMPORTANCE_LOW
            );
            
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(serviceChannel);
        }
    }
}
