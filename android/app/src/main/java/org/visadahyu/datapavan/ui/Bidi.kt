package org.visadahyu.datapavan.ui

private const val LEFT_TO_RIGHT_ISOLATE = '\u2066'
private const val POP_DIRECTIONAL_ISOLATE = '\u2069'

/**
 * Wraps a technical token that is always left-to-right (domain, IP address, package name,
 * version) in a Unicode left-to-right isolate, so that it cannot reorder the surrounding
 * sentence in right-to-left languages such as Persian or Arabic.
 *
 * Every such token must pass through this function before it is inserted into translated text.
 */
internal fun isolateLtr(token: String): String = "$LEFT_TO_RIGHT_ISOLATE$token$POP_DIRECTIONAL_ISOLATE"
