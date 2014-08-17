/**
 * Copyright (C) 2014 Open WhisperSystems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.textsecuregcm.tests.controllers;

import com.google.common.base.Optional;
import com.sun.jersey.api.client.ClientResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.controllers.DeviceController;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.DeviceResponse;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.PendingDevicesManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.VerificationCode;

import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;

import io.dropwizard.testing.junit.ResourceTestRule;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class DeviceControllerTest {
  @Path("/v1/devices")
  static class DumbVerificationDeviceController extends DeviceController {
    public DumbVerificationDeviceController(PendingDevicesManager pendingDevices, AccountsManager accounts, RateLimiters rateLimiters) {
      super(pendingDevices, accounts, rateLimiters);
    }

    @Override
    protected VerificationCode generateVerificationCode() {
      return new VerificationCode(5678901);
    }
  }

  private PendingDevicesManager pendingDevicesManager = mock(PendingDevicesManager.class);
  private AccountsManager       accountsManager       = mock(AccountsManager.class       );
  private RateLimiters          rateLimiters          = mock(RateLimiters.class          );
  private RateLimiter           rateLimiter           = mock(RateLimiter.class           );
  private Account               account               = mock(Account.class               );

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthenticator())
                                                            .addResource(new DumbVerificationDeviceController(pendingDevicesManager,
                                                                                                              accountsManager,
                                                                                                              rateLimiters))
                                                            .build();


  @Before
  public void setup() throws Exception {
    when(rateLimiters.getSmsDestinationLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getVoiceDestinationLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getVerifyLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getAllocateDeviceLimiter()).thenReturn(rateLimiter);
    when(rateLimiters.getVerifyDeviceLimiter()).thenReturn(rateLimiter);

    when(account.getNextDeviceId()).thenReturn(42L);

    when(pendingDevicesManager.getCodeForNumber(AuthHelper.VALID_NUMBER)).thenReturn(Optional.of("5678901"));
    when(accountsManager.get(AuthHelper.VALID_NUMBER)).thenReturn(Optional.of(account));
  }

  @Test
  public void validDeviceRegisterTest() throws Exception {
    VerificationCode deviceCode = resources.client().resource("/v1/devices/provisioning_code")
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, AuthHelper.VALID_PASSWORD))
        .get(VerificationCode.class);

    assertThat(deviceCode).isEqualTo(new VerificationCode(5678901));
    verify(rateLimiter).validate(AuthHelper.VALID_NUMBER);
    verify(pendingDevicesManager).store(AuthHelper.VALID_NUMBER, "5678901");
    reset(rateLimiter);

    DeviceResponse response = resources.client().resource("/v1/devices/5678901")
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_NUMBER, "password1"))
        .entity(new AccountAttributes("keykeykeykey", false, true, 1234))
        .type(MediaType.APPLICATION_JSON_TYPE)
        .put(DeviceResponse.class);

    assertThat(response.getDeviceId()).isEqualTo(42L);

    verify(pendingDevicesManager).remove(AuthHelper.VALID_NUMBER);
    verify(rateLimiter).validate(AuthHelper.VALID_NUMBER);

    ArgumentCaptor<Device> accountCaptor = ArgumentCaptor.forClass(Device.class);
    verify(account, times(1)).addDevice(accountCaptor.capture());
    Device device = accountCaptor.getValue();
    assertThat(device.getId()).isEqualTo(42);
    assertThat(device.getAuthenticationCredentials().verify("password1")).isTrue();
    assertThat(device.getSignalingKey()).isEqualTo("keykeykeykey");
    assertThat(device.getFetchesMessages()).isTrue();
  }

  @Test
  public void testVerifyCodeReturns401WhenAuthHeaderIsBad() throws Exception {
    ClientResponse response = resources.client().resource("/v1/devices/provisioning_code")
        .header("Authorization", "invalid_auth_header")
        .get(ClientResponse.class);

    assertThat(response.getStatus()).isEqualTo(401);
  }
}
