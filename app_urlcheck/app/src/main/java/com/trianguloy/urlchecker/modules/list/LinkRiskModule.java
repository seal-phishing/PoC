package com.trianguloy.urlchecker.modules.list;

import static com.trianguloy.urlchecker.utilities.methods.AndroidUtils.getStringWithPlaceholder;

import android.text.method.LinkMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.trianguloy.urlchecker.R;
import com.trianguloy.urlchecker.activities.ModulesActivity;
import com.trianguloy.urlchecker.dialogs.MainDialog;
import com.trianguloy.urlchecker.modules.AModuleConfig;
import com.trianguloy.urlchecker.modules.AModuleData;
import com.trianguloy.urlchecker.modules.AModuleDialog;
import com.trianguloy.urlchecker.modules.AutomationRules;
import com.trianguloy.urlchecker.modules.DescriptionConfig;
import com.trianguloy.urlchecker.url.UrlData;
import com.trianguloy.urlchecker.utilities.generics.GenericPref;
import com.trianguloy.urlchecker.utilities.methods.AndroidUtils;

import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class LinkRiskModule extends AModuleData {

    public static final String ID = "linkrisk";
    @Override public String getId() { return ID; }
    @Override public int getName() { return R.string.mLinkRisk_name; }
    @Override public AModuleDialog getDialog(MainDialog cntx) { return new LinkRiskDialog(cntx); }
    @Override public AModuleConfig getConfig(ModulesActivity cntx) {
        return new DescriptionConfig(getStringWithPlaceholder(cntx, R.string.mLinkRisk_desc, R.string.mLinkRisk_endpoint_hint));
    }
    @Override public List<AutomationRules.Automation<AModuleDialog>> getAutomations() {
        return (List<AutomationRules.Automation<AModuleDialog>>) (List<?>) LinkRiskDialog.AUTOMATIONS;
    }
}

class LinkRiskDialog extends AModuleDialog {

    private static final String PREF_ENDPOINT = "linkrisk_endpoint";
    private final GenericPref.Str endpointPref = new GenericPref.Str(
            PREF_ENDPOINT, "http://10.0.2.2:8001/check_url", getActivity()
    );

    private String lastAnalyzedUrl = null;

    static final List<AutomationRules.Automation<LinkRiskDialog>> AUTOMATIONS = List.of(
            new AutomationRules.Automation<>("analyze", R.string.mLinkRisk_auto, d -> d.runCheck(d.getUrlData().disableUpdates))
    );

    private Button analyzeBtn;
    private TextView info;
    private Thread thread;

    public LinkRiskDialog(MainDialog dialog) { super(dialog); }
    @Override public int getLayoutId() { return R.layout.button_text; }

    @Override public void onInitialize(View v) {
        analyzeBtn = v.findViewById(R.id.button);
        analyzeBtn.setText(R.string.mLinkRisk_check);
        analyzeBtn.setOnClickListener(x -> runCheck(false));
        info = v.findViewById(R.id.text);
        info.setMovementMethod(LinkMovementMethod.getInstance());
    }
    @Override
    public void onPrepareUrl(UrlData urlData) {
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
    }

    @Override
    public void onDisplayUrl(UrlData urlData) {
        // reset UI
        analyzeBtn.setEnabled(true);
        info.setText("");
        AndroidUtils.clearRoundedColor(info);

        // auto-run si nouvelle URL
        final String current = getUrl();
        if (current != null && !current.equals(lastAnalyzedUrl)) {
            lastAnalyzedUrl = current;
            runCheck(true); // lance l’analyse automatiquement
        }
    }


    private void runCheck(boolean disableUpdates){
        analyzeBtn.setEnabled(false);
        info.setText(R.string.mLinkRisk_checking);
        AndroidUtils.clearRoundedColor(info);
        final String endpoint = endpointPref.get();
        final String urlToCheck = getUrl();
        thread = new Thread(() -> {
            try{
                JSONObject body = new JSONObject(); body.put("url", urlToCheck);
                JSONObject resp = new JSONObject(postJson(endpoint, body.toString()));
                if(Thread.currentThread().isInterrupted()) return;

                final String verdict = resp.optString("verdict","unknown");
                final String source  = resp.optString("source", null);
                final double proba   = resp.optDouble("proba",-1.0);

                getActivity().runOnUiThread(() -> {
                    final boolean fromExternalList =
                            source != null && (
                                    source.toLowerCase().contains("ofcs") ||
                                            source.toLowerCase().contains("google") ||
                                            source.toLowerCase().contains("urlhaus")
                            );
                    final boolean fromML = "ML".equalsIgnoreCase(source);

                    if ("phishing".equalsIgnoreCase(verdict) && fromExternalList) {
                        // Cas listes externes -> "Phishing détecté (source : ...)"
                        info.setText(getActivity().getString(R.string.mLinkRisk_detected, source));
                        AndroidUtils.setRoundedColor(R.color.bad, info);

                    } else if ("phishing".equalsIgnoreCase(verdict) && fromML) {
                        // Cas ML -> "Risque élevé (source : ML)"
                        info.setText(getActivity().getString(R.string.mLinkRisk_risk_high, "ML"));
                        AndroidUtils.setRoundedColor(R.color.bad, info);

                    } else if ("suspect".equalsIgnoreCase(verdict)) {
                        // Cas suspect -> "Risque modéré", + source ML si présent
                        if (fromML) {
                            info.setText(getActivity().getString(R.string.mLinkRisk_risk_medium, "ML"));
                        } else {
                            info.setText(R.string.mLinkRisk_risk_medium);
                        }
                        AndroidUtils.setRoundedColor(R.color.warning, info);

                    } else if ("legitimate".equalsIgnoreCase(verdict)) {
                        // Cas faible -> "Risque faible", + source ML si présent, et couleur neutre
                        if (fromML) {
                            info.setText(getActivity().getString(R.string.mLinkRisk_risk_low, "ML"));
                        } else {
                            info.setText(R.string.mLinkRisk_risk_low);
                        }
                        AndroidUtils.setRoundedColor(R.color.neutral, info); // <— neutre (plus de vert)

                    } else {
                        info.setText(R.string.mLinkRisk_unavailable);
                        AndroidUtils.clearRoundedColor(info);
                    }

                    analyzeBtn.setEnabled(true);
                });

            } catch(Exception e){
                if(Thread.currentThread().isInterrupted()) return;
                getActivity().runOnUiThread(() -> {
                    info.setText(getActivity().getString(R.string.mLinkRisk_error, e.getMessage()));
                    AndroidUtils.setRoundedColor(R.color.warning, info);
                    analyzeBtn.setEnabled(true);
                });
            }
        });
        thread.start();
    }

    private static String postJson(String endpoint, String json) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
        try {
            conn.setConnectTimeout(8000); conn.setReadTimeout(15000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type","application/json; charset=utf-8");
            try (OutputStream os = conn.getOutputStream()){
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            InputStream is = (code>=200 && code<300) ? conn.getInputStream() : conn.getErrorStream();
            try(BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))){
                StringBuilder sb = new StringBuilder(); String line;
                while((line = br.readLine()) != null) sb.append(line);
                if(code<200 || code>=300) throw new IOException("HTTP "+code+" "+sb);
                return sb.toString();
            }
        } finally { conn.disconnect(); }
    }
}
