package org.visadahyu.datapavan.watch.log

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import java.util.concurrent.TimeUnit

/**
 * Runs the connection log's expiry about every six hours, for the days when nothing else starts Watch
 * (ADR 0037): a tunnel turned off before a trip still loses its old days. Android decides when a job
 * runs, and on some makers' phones it seldom runs one for an app the user has not opened in a long time.
 * The job does not survive a restart of the phone (that would need the permission to start at boot,
 * which ADR 0034 does not give Watch); the next start of Watch's process schedules it again, and expires
 * the log itself as it does.
 */
class LogExpiryJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        ConnectionLog.of(this).expire { jobFinished(params, false) }
        return true
    }

    /** Android stopped the job early: the next period runs it again. */
    override fun onStopJob(params: JobParameters): Boolean = false

    companion object {
        private const val ID = 37
        private val PERIOD = TimeUnit.HOURS.toMillis(6)

        /** Schedules the job unless it is already pending ([keep]), or cancels it. */
        fun keep(context: Context, keep: Boolean) {
            val jobs = context.getSystemService(JobScheduler::class.java) ?: return
            if (!keep) {
                jobs.cancel(ID)
                return
            }
            if (jobs.getPendingJob(ID) != null) return
            jobs.schedule(JobInfo.Builder(ID, ComponentName(context, LogExpiryJob::class.java)).setPeriodic(PERIOD).build())
        }
    }
}
