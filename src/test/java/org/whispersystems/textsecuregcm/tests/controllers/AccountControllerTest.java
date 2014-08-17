package org.whispersystems.textsecuregcm.tests.controllers;

import com.google.common.base.Optional;
import com.sun.jersey.api.client.ClientResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.auth.AuthenticationCredentials;
import org.whispersystems.textsecuregcm.controllers.AccountController;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.sms.SmsSender;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.PendingAccountsManager;
import org.whispersystems.textsecuregcm.storage.StoredMessages;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;

import javax.ws.rs.core.MediaType;

import io.dropwizard.testing.junit.ResourceTestRule;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class AccountControllerTest {

  private static final String SENDER = "+14152222222";

  private PendingAccountsManager pendingAccountsManager = mock(PendingAccountsManager.class);
  private AccountsManager        accountsManager        = mock(AccountsManager.class       );
  private RateLimiters           rateLimiters           = mock(RateLimiters.class          );
  private RateLimiter            rateLimiter            = mock(RateLimiter.class           );
  private SmsSender              smsSender              = mock(SmsSender.class             );
  private StoredMessages         storedMessages         = mock(StoredMessages.class        );

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthenticator())
                                                            .addResource(new AccountController(pendingAccountsManager,
                                                                                               accountsManager,
                                                                                               rateLimiters,
                                                                                               smsSender,
                                                                                               storedMessages))
                                                            .build();


  @Before
  public void setup() throws Exception {
    when(rateLimiters.getSmsDestinationLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getVoiceDestinationLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getVerifyLimiter()).thenReturn(rateLimiter);

    when(pendingAccountsManager.getCodeForNumber(SENDER)).thenReturn(Optional.of("1234"));
  }

  @Test
  public void testSendCode() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/sms/code/%s", SENDER))
            .get(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(200);

    verify(smsSender).deliverSmsVerification(eq(SENDER), anyString());
    verify(rateLimiter).validate(eq(SENDER));
    verify(pendingAccountsManager).store(eq(SENDER), anyString());
  }

  @Test
  public void testSendCodeViaVoice() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/voice/code/%s", SENDER))
            .get(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(200);

    verify(smsSender).deliverVoxVerification(eq(SENDER), anyString());
    verify(rateLimiter).validate(eq(SENDER));
    verify(pendingAccountsManager).store(eq(SENDER), anyString());
  }

  @Test
  public void testSendCodeViaUnknownTransport() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/unknown_transport/code/%s", SENDER))
            .get(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(422);

    verifyNoMoreInteractions(pendingAccountsManager, smsSender, rateLimiter);
  }

  @Test
  public void testSendCodeWithNonNumbericSender() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/sms/code/%s", "invalid_number"))
            .get(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(400);

    verifyNoMoreInteractions(smsSender);
  }

  @Test
  public void testVerifyCode() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/code/%s", "1234"))
            .header("Authorization", AuthHelper.getAuthHeader(SENDER, "bar"))
            .entity(new AccountAttributes("keykeykeykey", false, false, 2222))
            .type(MediaType.APPLICATION_JSON_TYPE)
            .put(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(204);

    ArgumentCaptor<Account> accountCaptor = ArgumentCaptor.forClass(Account.class);
    verify(rateLimiter).validate(eq(SENDER));
    verify(accountsManager, times(1)).create(accountCaptor.capture());
    Account account = accountCaptor.getValue();
    assertThat(account.getNumber()).isEqualTo(SENDER);
    assertThat(account.getSupportsSms()).isFalse();

    Device device = account.getDevice(Device.MASTER_ID).get();
    assertThat(device.getId()).isEqualTo(Device.MASTER_ID);
    assertThat(device.getAuthenticationCredentials().verify("bar")).isTrue();
    assertThat(device.getSignalingKey()).isEqualTo("keykeykeykey");
    assertThat(device.getFetchesMessages()).isFalse();
    assertThat(device.getRegistrationId()).isEqualTo(2222);
  }

  @Test
  public void testVerifyBadCode() throws Exception {
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/code/%s", "1111"))
            .header("Authorization", AuthHelper.getAuthHeader(SENDER, "bar"))
            .entity(new AccountAttributes("keykeykeykey", false, false, 3333))
            .type(MediaType.APPLICATION_JSON_TYPE)
            .put(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(403);

    verifyNoMoreInteractions(accountsManager);
  }

  @Test
  public void testVerifyCodeFromRelayListedNumber() throws Exception {
    when(accountsManager.isRelayListed(SENDER)).thenReturn(true);
    ClientResponse response =
        resources.client().resource(String.format("/v1/accounts/code/%s", "1234"))
            .header("Authorization", AuthHelper.getAuthHeader(SENDER, "bar"))
            .entity(new AccountAttributes("keykeykeykey", false, false, 2222))
            .type(MediaType.APPLICATION_JSON_TYPE)
            .put(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(417);

    verify(accountsManager).isRelayListed(anyString());
    verify(accountsManager, times(0)).create(any(Account.class));
    verify(rateLimiter).validate(eq(SENDER));
  }

}