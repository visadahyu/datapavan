package org.visadahyu.datapavan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import org.visadahyu.datapavan.core.NativeCore
import org.visadahyu.datapavan.ui.DatapavanApp
import org.visadahyu.datapavan.ui.DatapavanTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val engineVersion = NativeCore.version()
        setContent {
            DatapavanTheme {
                DatapavanApp(engineVersion = engineVersion)
            }
        }
    }
}
