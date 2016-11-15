/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 **/

package org.codice.ddf.security.sts.client;

import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StsClientTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(StsClientTest.class);

    @Test
    public void testGetToken() {

        SecurityToken token = null;
        try {
            LOGGER.info("Retrieving security token...");
            StsClient client = new StsClient();
            token = client.requestSecurityToken("admin", "admin");
            LOGGER.info("token retrieved {}", token.getId());
        } catch (Exception e) {
            LOGGER.error("Unable to get security token", e);
        }
        assertThat(token, notNullValue());

    }

}
