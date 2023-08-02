/**
 * Copyright (c) 2010-2022 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.http.internal.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentProvider;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.FormContentProvider;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The {@link HttpThingConfig} class contains fields mapping thing configuration parameters.
 *
 * @author Jan N. Klug - Initial contribution
 */
@NonNullByDefault
public class HttpThingConfig {
    private final Logger logger = LoggerFactory.getLogger(HttpThingConfig.class);
    public String baseURL = "";
    public int refresh = 30;
    public int timeout = 3000;
    public int delay = 0;

    public String username = "";
    public String password = "";

    public String clientId = "";
    public String clientSecret = "";
    public String scope = "";
    public String grantType = "";
    public String tokenUrl = "";
    public Integer oAuth2TokenLifeTime = 0;
    public Instant oAuth2TokenTimestamp = Instant.now();

    public HttpAuthMode authMode = HttpAuthMode.BASIC;
    public HttpMethod stateMethod = HttpMethod.GET;

    public HttpMethod commandMethod = HttpMethod.GET;
    public int bufferSize = 2048;

    public @Nullable String encoding = null;
    public @Nullable String contentType = null;

    public boolean ignoreSSLErrors = false;

    // ArrayList is required as implementation because list may be modified later
    public ArrayList<String> headers = new ArrayList<>();

    public Boolean checkOAuth2Fields() {

        if (!(this.authMode == HttpAuthMode.OAuthV2))
            return (true);

        return (!this.clientId.isEmpty() && !this.clientSecret.isEmpty() && !this.scope.isEmpty()
                && !this.grantType.isEmpty() && !this.tokenUrl.isEmpty());
    }

    public String requestOAuthToken() {

        HttpClient secureClient = new HttpClient(new SslContextFactory.Client());
        try {
            secureClient.start();
            URI uri = new URI(this.tokenUrl);

            Fields fields = new Fields();
            fields.add("client_id", this.clientId);
            fields.add("client_secret", this.clientSecret);
            fields.add("scope", this.scope);
            fields.add("grant_type", this.grantType);

            ContentProvider contentProvider = new FormContentProvider(fields, StandardCharsets.UTF_8);

            Request request = secureClient.newRequest(uri).content(contentProvider)
                    .timeout(this.timeout, TimeUnit.MILLISECONDS).method(HttpMethod.GET);

            ContentResponse contentResponse = request.send();

            if (HttpStatus.isSuccess(contentResponse.getStatus())) {
                JsonObject jsonObject = JsonParser.parseString(contentResponse.getContentAsString()).getAsJsonObject();

                oAuth2TokenTimestamp = Instant.now();
                oAuth2TokenLifeTime = jsonObject.get("expires_in").getAsInt();

                return new String(jsonObject.get("token_type").toString().replaceAll("\"", "") + " "
                        + jsonObject.get("access_token").toString().replaceAll("\"", ""));
            }
            secureClient.stop();
        } catch (URISyntaxException e) {
            logger.debug("Failed to create authentication: Url '{}' is invalid", this.tokenUrl);
        } catch (Exception e) {
            logger.debug("OAuth V2 Authentication Request have faild - see Message:'{}'", e.getMessage());
        }
        return "";
    }

    public boolean isTokenLifetimeExpired() {
        return isTokenLifetimeExpired(Duration.ofMillis(0));
    }

    public boolean isTokenLifetimeExpired(Duration offset) {
        Duration duration = Duration.between(oAuth2TokenTimestamp.plusSeconds(oAuth2TokenLifeTime),
                Instant.now().plus(offset));

        return !duration.isNegative() || duration.isZero();
    }
}
