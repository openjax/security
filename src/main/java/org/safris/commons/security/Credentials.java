/* Copyright (c) 2016 lib4j
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * You should have received a copy of The MIT License (MIT) along with this
 * program. If not, see <http://opensource.org/licenses/MIT/>.
 */

package org.safris.commons.security;

import java.io.Serializable;

public final class Credentials implements Serializable {
  private static final long serialVersionUID = -8959414770636711960L;

  public final String username;
  public final String password;

  public Credentials(final String username, final String password) {
    this.username = username;
    if (username == null)
      throw new NullPointerException("username == null");

    this.password = password;
    if (password == null)
      throw new NullPointerException("password == null");
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this)
      return true;

    if (!(obj instanceof Credentials))
      return false;

    final Credentials that = (Credentials)obj;
    return username.equals(that.username) && password.equals(that.password);
  }

  @Override
  public int hashCode() {
    int hashCode = 9;
    hashCode ^= 31 * username.hashCode();
    hashCode ^= 31 * password.hashCode();
    return hashCode;
  }
}