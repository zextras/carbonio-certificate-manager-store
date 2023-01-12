package com.zimbra.cert.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Simple date formatter.
 */
public class DateFormatter {
  private static final String DATE_PATTERN = "MMM dd yyyy HH:mm:ss z";

  private DateFormatter() {
    throw new RuntimeException("Utility class cannot be instantiated.");
  }

  /**
   * Provides string representation using the preassigned pattern of the given date.
   * @param date date that you want to get a string representation from.
   * @return string representation of a given date.
   */
  public static String formatDate(Date date) {
    DateFormat dateFormat = new SimpleDateFormat(DATE_PATTERN);
    return dateFormat.format(date);
  }

}
