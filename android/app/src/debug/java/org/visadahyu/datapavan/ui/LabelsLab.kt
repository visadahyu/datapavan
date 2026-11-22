package org.visadahyu.datapavan.ui

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import android.os.LocaleList
import java.io.PrintWriter
import java.text.Normalizer
import java.util.Locale
import org.visadahyu.datapavan.core.NativePacks
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.OtherAppResources
import org.visadahyu.datapavan.labels.PhoneLabels

/**
 * Debug builds only (ADR 0054): Android's own labels as this phone holds them, through MainActivity's dump, in both
 * editions and with no VPN started. Nothing of the system app runs: its resource table is read as a launcher reads an
 * app's name, and nothing is decompiled.
 *
 * `adb shell dumpsys activity org.visadahyu.datapavan/.MainActivity labels-read` prints, for every key of the data
 * pack's rows and each of Datapavan's eight languages, the label as Datapavan reads it with the phone set to that
 * language: `label KEY LANG SOURCE PACKAGE/NAME TEXT` (scripts/verify-labels.sh compares it with AOSP's text).
 *
 * `... labels-find LANG [--contains] [--package PACKAGE] TEXT` lists the string resources of a system app (Settings
 * unless named) whose text in LANG is TEXT, after cleaning and NFC, or contains it: `found NAME`, then the text in
 * each of the eight languages, so that a maker's names are found from one screen in one language. It enumerates the
 * package's own string resources by ID through Android's resources API, and refuses a package that is not a system
 * app.
 */
object LabelsLab {
    private val LANGUAGES = listOf("en", "fa", "ar", "fr", "de", "es", "ru", "zh-CN")

    fun dump(context: Context, args: List<String>, writer: PrintWriter) {
        when (args.first()) {
            "labels-read" -> read(context, writer)
            "labels-find" -> find(context, args.drop(1), writer)
            else -> writer.println("labels: unknown command ${args.first()}")
        }
        writer.flush()
    }

    private fun read(context: Context, writer: PrintWriter) {
        val text = DataPackStore.get(context, NativePacks).text(LabelRow.PATH)
        val rows = text?.let(LabelRow::parse).orEmpty()
        writer.println("labels-read maker ${Build.MANUFACTURER.orEmpty().lowercase(Locale.ROOT)} sdk ${Build.VERSION.SDK_INT} rows ${rows.size}")
        val keys = rows.map { it.key }.distinct()
        for (language in LANGUAGES) {
            val locale = Locale.forLanguageTag(language)
            val labels = PhoneLabels.of(context, { text }, AndroidLabels::fallback, phone = listOf(locale), own = listOf(locale))
            for (key in keys) {
                val label = labels.label(key)
                val place = label.row?.let { "${it.packageName ?: "handler:" + it.handler}/${it.name}" } ?: "-"
                writer.println("label $key ${locale.language} ${label.source.name.lowercase(Locale.ROOT)} $place ${label.text}")
            }
        }
        writer.println("labels-read done")
    }

    private fun find(context: Context, args: List<String>, writer: PrintWriter) {
        var contains = false
        var packageName = "com.android.settings"
        val words = mutableListOf<String>()
        var i = 1
        while (i < args.size) {
            when (args[i]) {
                "--contains" -> contains = true
                "--package" -> packageName = args.getOrNull(++i).orEmpty()
                else -> words += args[i]
            }
            i++
        }
        val language = args.firstOrNull()
        val wanted = normal(words.joinToString(" "))
        if (language == null || wanted.isEmpty()) {
            writer.println("labels-find usage: labels-find LANG [--contains] [--package PACKAGE] TEXT")
            return
        }
        if (!PhoneLabels.isSystem(context, packageName)) {
            writer.println("labels-find refused $packageName: not a system app")
            return
        }
        val other = try {
            context.createPackageContext(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            writer.println("labels-find refused $packageName: not installed")
            return
        }
        val labelRes = other.applicationInfo.labelRes
        if (labelRes == 0) {
            writer.println("labels-find refused $packageName: it names no label resource, so its string type is not known")
            return
        }
        // A resource ID is 0xPPTTEEEE: the package's ID, the type's, then the entry's. The app's own label is one of its
        // strings, so its ID gives the string type of the package's table, SettingsLib's merged strings included.
        val base = (labelRes and 0xff000000.toInt()) or (labelRes and 0x00ff0000)
        val inLanguage = resources(other, Locale.forLanguageTag(language))
        val all = LANGUAGES.associateWith { resources(other, Locale.forLanguageTag(it)) }
        var misses = 0
        var entries = 0
        var found = 0
        var entry = 0
        while (entry <= 0xffff && misses < 4096) {
            val id = base or entry
            entry++
            val name = try {
                inLanguage.getResourceEntryName(id)
            } catch (e: Resources.NotFoundException) {
                misses++
                continue
            }
            misses = 0
            entries++
            val value = try {
                normal(inLanguage.getString(id))
            } catch (e: Resources.NotFoundException) {
                continue
            }
            if (value == wanted || (contains && wanted in value)) {
                found++
                writer.println("found string/$name")
                for ((tag, resources) in all) {
                    val text = try {
                        OtherAppResources.clean(resources.getString(id))
                    } catch (e: Resources.NotFoundException) {
                        "-"
                    }
                    writer.println("  $tag $text")
                }
            }
        }
        writer.println("labels-find done $packageName $found of $entries strings")
    }

    private fun normal(text: String): String = Normalizer.normalize(OtherAppResources.clean(text), Normalizer.Form.NFC)

    private fun resources(other: Context, locale: Locale): Resources =
        other.createConfigurationContext(Configuration(other.resources.configuration).apply { setLocales(LocaleList(locale)) }).resources
}
