package de.markusfisch.android.binaryeye.fragment

import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.support.design.widget.FloatingActionButton
import android.support.v4.app.Fragment
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.*
import android.widget.EditText
import android.widget.TableLayout
import android.widget.TableRow
import android.widget.TextView
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import de.markusfisch.android.binaryeye.R
import de.markusfisch.android.binaryeye.actions.ActionRegistry
import de.markusfisch.android.binaryeye.actions.wifi.WifiAction
import de.markusfisch.android.binaryeye.actions.wifi.WifiConnector
import de.markusfisch.android.binaryeye.activity.MainActivity
import de.markusfisch.android.binaryeye.adapter.prettifyFormatName
import de.markusfisch.android.binaryeye.app.*
import de.markusfisch.android.binaryeye.content.copyToClipboard
import de.markusfisch.android.binaryeye.content.shareText
import de.markusfisch.android.binaryeye.database.Scan
import de.markusfisch.android.binaryeye.io.askForFileName
import de.markusfisch.android.binaryeye.io.toSaveResult
import de.markusfisch.android.binaryeye.io.writeExternalFile
import de.markusfisch.android.binaryeye.view.setPaddingFromWindowInsets
import de.markusfisch.android.binaryeye.widget.toast
import kotlinx.coroutines.*
import kotlin.io.path.createTempDirectory


class DecodeFragment : Fragment() {
	private lateinit var contentView: EditText
	private lateinit var formatView: TextView
	private lateinit var dataView: TableLayout
	private lateinit var metaView: TableLayout
	private lateinit var hexView: TextView
	private lateinit var format: String
	private lateinit var fab: FloatingActionButton
	private lateinit var securityView : TextView

	private val parentJob = Job()
	private val scope: CoroutineScope = CoroutineScope(Dispatchers.Main + parentJob)
	private val content: String
		get() = contentView.text.toString()

	private var closeAutomatically = false
	private var action = ActionRegistry.DEFAULT_ACTION
	private var isBinary = false
	private var raw: ByteArray = ByteArray(0)
	private var id = 0L
	private var reportContent = ""

	override fun onCreate(state: Bundle?) {
		super.onCreate(state)
		setHasOptionsMenu(true)
	}

	override fun onCreateView(
		inflater: LayoutInflater,
		container: ViewGroup?,
		state: Bundle?
	): View {
		activity?.setTitle(R.string.content)

		val view = inflater.inflate(
			R.layout.fragment_decode,
			container,
			false
		)

		closeAutomatically = prefs.closeAutomatically &&
				activity?.intent?.hasExtra(MainActivity.DECODED) == true

		val scan = arguments?.getParcelable(SCAN) as Scan?
			?: throw IllegalArgumentException("DecodeFragment needs a Scan")
		id = scan.id

		val inputContent = scan.content
		isBinary = scan.raw != null
		raw = scan.raw ?: inputContent.toByteArray()
		reportContent = scan.report // Store scan result into variable
		format = scan.format

		contentView = view.findViewById(R.id.content)
		fab = view.findViewById(R.id.open)

		if (!isBinary) {
			contentView.setText(inputContent)
			contentView.addTextChangedListener(object : TextWatcher {
				override fun afterTextChanged(s: Editable?) {
					updateViewsAndAction(content.toByteArray(), reportContent)
				}

				override fun beforeTextChanged(
					s: CharSequence?,
					start: Int,
					count: Int,
					after: Int
				) {
				}

				override fun onTextChanged(
					s: CharSequence?,
					start: Int,
					before: Int,
					count: Int
				) {
				}
			})
			fab.setOnClickListener {
				executeAction(content.toByteArray())
			}
			if (prefs.openImmediately) {
				executeAction(content.toByteArray())
			}
		} else {
			contentView.setText(String(raw).foldNonAlNum())
			contentView.isEnabled = false
			fab.setImageResource(R.drawable.ic_action_save)
			fab.setOnClickListener {
				askForFileNameAndSave(raw)
			}
		}

		formatView = view.findViewById(R.id.format)
		dataView = view.findViewById(R.id.data)
		metaView = view.findViewById(R.id.meta)
		hexView = view.findViewById(R.id.hex)
		securityView = view.findViewById(R.id.security) // Assign area to place security result

		GlobalScope.launch(Dispatchers.Main) { // launch the coroutine immediately
			generateReport()
		}
		updateViewsAndAction(raw, reportContent)

		if (!isBinary) {
			fillDataView(dataView, inputContent)
		}

		if (prefs.showMetaData) {
			fillMetaView(metaView, scan)
		}

		(view.findViewById(R.id.inset_layout) as View).setPaddingFromWindowInsets()
		(view.findViewById(R.id.scroll_view) as View).setPaddingFromWindowInsets()

		return view
	}

	private suspend fun generateReport() {
		// Introduce Python
		val py = Python.getInstance()

		// Retrieve the analyser script
		val module = py.getModule("analyser")

		// If no result then return 0"
		val result = module.callAttr("analyser", content).toString()
		Log.d("Result", result)

		if (result == "url" || result == "file") {
			var retries = 3
			val delay: Long = 10000

			while (retries >= 0) { // More than to account for weird scenarios
				var value = 0
				if (result == "url") {
					value = checkURL(module)
				} else if (result == "file") {
					value = checkFile(module)
				}

				if (value !=0) {
					when (value) {
						1 -> securityView.setTextColor(Color.GREEN)
						2 -> securityView.setTextColor(Color.YELLOW)
						3 -> securityView.setTextColor(Color.RED)
					}
					Log.d("Report", "I JUST CHANGED THE COLOUR TO $value")
					break
				}

				if (retries == 0) {
					securityView.setTextColor(Color.RED)
					reportContent = "Scan timed out. Please try again later."
					updateViewsAndAction(raw, reportContent)
				} else {
					Log.d("Test", "$retries")
					retries--
					delay(delay)
				}
			}
		} else if (result == "wifi") { // Do stuff for Wi-Fi's
			val report = module.callAttr("get_wifi_analysis").toString()
			Log.d("Wi-Fi Result", report)

			var unsafe = false
			when {
				report.contains("hidden") -> reportContent += "This network is hidden.\n"
				report.contains("nopass") -> {
					reportContent += "This network does not require a password!\n"
					unsafe = true
				}
				report.contains("noauth") -> {
					reportContent += "This network is not encrypted!\n"
					unsafe = true
				}
				report.contains("authWEP") -> {
					reportContent += "This network uses the outdated WEP encryption!\n"
					unsafe = true
				}
			}
			if (unsafe) {
				securityView.setTextColor(Color.RED)
				reportContent += "This network is not safe to join."
			} else {
				securityView.setTextColor(Color.GREEN)
				reportContent += "This network appears to be safe."
			}
			updateViewsAndAction(raw, reportContent)
		}
	}

	private fun checkURL(module: PyObject): Int {
		var value = 0
		val (Green, Yellow, Red) = listOf(1, 2, 3)
		val report = module.callAttr("get_url_analysis").toString()
		Log.d("URL Report Value", report)
		when (report) {
			"1" -> {
				value = if (value < Red) Red else value
				reportContent =
					"Unable to generate a report. Please scan again or proceed with caution."
			}
			"2" -> {
				securityView.setTextColor(Color.YELLOW)
				reportContent = "Report is not ready yet. Please wait..."
			}
			"3" -> {
				value = if (value < Green) Green else value
				reportContent = "There was an error with the request. Aborting..."
			}
			else -> {
				val conclusion = module.callAttr("get_url_conclusion").toString()
				when (conclusion) {
					"malicious" -> {
						value = if (value < Red) Red else value
						reportContent =
							"This domain appears to be malicious. Avoiding this website is recommended.\n"
					}
					"suspicious" -> {
						value = if (value < Yellow) Yellow else value
						reportContent =
							"This domain appears to be suspicious. Proceed with caution.\n"
					}
					"harmless" -> {
						value = if (value < Green) Green else value
						reportContent = "This domain appears to be safe.\n"
					}
				}

				val creationDate = module.callAttr("get_url_creation_date").toInt()
				if (creationDate == 0) {
					Log.d("Creation Date", "Unable to retrieve creation date")
				} else if (creationDate < 31) {
					value = if (value < Yellow) Yellow else value
					reportContent += "This URL was registered in the last month. Proceed with caution.\n"
				} else {
					value = if (value < Green) Green else value
					reportContent += "This URL was registered over a month ago.\n"
				}

				val downloadable = module.callAttr("get_url_downloadable").toString()
				when (downloadable) {
					"True" -> {
						value = if (value < Yellow) Yellow else value
						reportContent += "This URL attempts to download a file. Proceed with caution."
					}
				}
			}
		}
		updateViewsAndAction(raw, reportContent)
		return value
	}

	private suspend fun checkFile(module: PyObject): Int {
		var value = 0
		val (Green, Yellow, Red) = listOf(1, 2, 3)
		delay(2000)
		val report = module.callAttr("get_file_analysis").toString()
		Log.d("File Report Value", report)
		when (report) {
			"1" -> {
				value = if (value < Red) Red else value
				reportContent =
					"Unable to generate a report. Please scan again or proceed with caution."
			}
			"2" -> {
				securityView.setTextColor(Color.YELLOW)
				reportContent = "Report is not ready yet. Please wait..."
			}
			"3" -> {
				value = if (value < Red) Red else value
				reportContent = "There was an error with the request. Aborting..."
			}
			else -> {
				when (report) {
					"malicious" -> {
						value = if (value < Red) Red else value
						reportContent =
							"This QRCode appears to be malicious.\n"
					}
					"suspicious" -> {
						value = if (value < Yellow) Yellow else value
						reportContent =
							"This QRCode appears to be suspicious.\n"
					}
					"harmless" -> {
						value = if (value < Green) Green else value
						reportContent = "This QRCode appears to be safe.\n"
					}
				}
			}
		}
		updateViewsAndAction(raw, reportContent)
		return value
	}

	override fun onDestroy() {
		super.onDestroy()
		parentJob.cancel()
	}

	private fun updateViewsAndAction(bytes: ByteArray, report: String?) {
		val prevAction = action
		if (!prevAction.canExecuteOn(bytes)) {
			action = ActionRegistry.getAction(bytes)
		}
		formatView.text = resources.getQuantityString(
			R.plurals.barcode_info,
			bytes.size,
			prettifyFormatName(format),
			bytes.size
		)
		hexView.text = if (prefs.showHexDump) hexDump(bytes) else ""
		// Show the scan results
		securityView.text = if (prefs.showHexDump) report else ""
		if (prevAction !== action) {
			fab.setImageResource(action.iconResId)
			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
				fab.setOnLongClickListener { v ->
					v.context.toast(action.titleResId)
					true
				}
			} else {
				fab.tooltipText = getString(action.titleResId)
			}
		}
	}

	private fun fillDataView(tableLayout: TableLayout, content: String) {
		val items = LinkedHashMap<Int, String?>()
		if (action is WifiAction) {
			WifiConnector.parseMap(content)?.let { wifiData ->
				items.putAll(
					linkedMapOf(
						R.string.entry_type to getString(R.string.wifi_network),
						R.string.wifi_ssid to wifiData["S"],
						R.string.wifi_password to wifiData["P"],
						R.string.wifi_type to wifiData["T"],
						R.string.wifi_hidden to wifiData["H"],
						R.string.wifi_eap to wifiData["E"],
						R.string.wifi_identity to wifiData["I"],
						R.string.wifi_anonymous_identity to wifiData["A"],
						R.string.wifi_phase2 to wifiData["PH2"]
					)
				)
			}
		}
		fillDataTable(tableLayout, items)
	}

	private fun fillMetaView(tableLayout: TableLayout, scan: Scan) {
		fillDataTable(
			tableLayout, linkedMapOf(
				R.string.error_correction_level to scan.errorCorrectionLevel,
				R.string.issue_number to scan.issueNumber,
				R.string.orientation to scan.orientation,
				R.string.other_meta_data to scan.otherMetaData,
				R.string.pdf417_extra_metadata to scan.pdf417ExtraMetaData,
				R.string.possible_country to scan.possibleCountry,
				R.string.suggested_price to scan.suggestedPrice,
				R.string.upc_ean_extension to scan.upcEanExtension
			)
		)
	}

	private fun fillDataTable(
		tableLayout: TableLayout,
		items: LinkedHashMap<Int, String?>
	) {
		val ctx = tableLayout.context
		val spaceBetween = (16f * ctx.resources.displayMetrics.density).toInt()
		items.forEach { item ->
			val text = item.value
			if (!text.isNullOrBlank()) {
				val tr = TableRow(ctx)
				val keyView = TextView(ctx)
				keyView.setText(item.key)
				val valueView = TextView(ctx)
				valueView.setPadding(spaceBetween, 0, 0, 0)
				valueView.text = text
				tr.addView(keyView)
				tr.addView(valueView)
				tableLayout.addView(tr)
			}
		}
		if (tableLayout.childCount > 0) {
			tableLayout.setPadding(0, 0, 0, spaceBetween)
		}
	}

	override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
		inflater.inflate(R.menu.fragment_decode, menu)
		if (isBinary) {
			menu.findItem(R.id.copy_to_clipboard).isVisible = false
			menu.findItem(R.id.create).isVisible = false
		}
		if (id > 0L) {
			menu.findItem(R.id.remove).isVisible = true
		}
		if (action is WifiAction) {
			menu.findItem(R.id.copy_password).isVisible = true
		}
	}

	override fun onOptionsItemSelected(item: MenuItem): Boolean {
		return when (item.itemId) {
			R.id.copy_password -> {
				copyPasswordToClipboard()
				maybeBackOrFinish()
				true
			}
			R.id.copy_to_clipboard -> {
				copyToClipboard(textOrHex())
				maybeBackOrFinish()
				true
			}
			R.id.share -> {
				context?.apply {
					shareText(textOrHex())
					maybeBackOrFinish()
				}
				true
			}
			R.id.create -> {
				fragmentManager?.addFragment(
					EncodeFragment.newInstance(content, format)
				)
				true
			}
			R.id.remove -> {
				db.removeScan(id)
				backOrFinish()
				true
			}
			else -> super.onOptionsItemSelected(item)
		}
	}

	private fun textOrHex() = if (isBinary) {
		raw.toHexString()
	} else {
		content
	}

	private fun copyPasswordToClipboard() {
		val ac = action
		if (ac is WifiAction) {
			ac.password?.let { password ->
				activity?.apply {
					copyToClipboard(password)
					toast(R.string.copied_password_to_clipboard)
				}
			}
		}
	}

	private fun copyToClipboard(text: String) {
		activity?.apply {
			copyToClipboard(text)
			toast(R.string.copied_to_clipboard)
		}
	}

	private fun maybeBackOrFinish() {
		if (closeAutomatically) {
			backOrFinish()
		}
	}

	private fun backOrFinish() {
		val fm = fragmentManager
		if (fm != null && fm.backStackEntryCount > 0) {
			fm.popBackStack()
		} else {
			activity?.finish()
		}
	}

	private fun executeAction(content: ByteArray) {
		val ac = activity ?: return
		if (content.isNotEmpty()) {
			if (action is WifiAction &&
				Build.VERSION.SDK_INT < Build.VERSION_CODES.Q &&
				!ac.hasLocationPermission { executeAction(content) }
			) {
				return
			}
			scope.launch {
				action.execute(ac, content)
				maybeBackOrFinish()
			}
		}
	}

	private fun askForFileNameAndSave(raw: ByteArray) {
		val ac = activity ?: return
		// Write permission is only required before Android Q.
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q &&
			!ac.hasWritePermission { askForFileNameAndSave(raw) }
		) {
			return
		}
		scope.launch(Dispatchers.Main) {
			val name = ac.askForFileName() ?: return@launch
			val message = ac.writeExternalFile(
				name,
				"application/octet-stream"
			) {
				it.write(raw)
			}.toSaveResult()
			ac.toast(message)
		}
	}

	companion object {
		private const val SCAN = "scan"

		fun newInstance(scan: Scan): Fragment {
			val args = Bundle()
			args.putParcelable(SCAN, scan)
			val fragment = DecodeFragment()
			fragment.arguments = args
			return fragment
		}
	}
}

private fun hexDump(bytes: ByteArray, charsPerLine: Int = 33): String {
	if (charsPerLine < 4 || bytes.isEmpty()) {
		return ""
	}
	val dump = StringBuilder()
	val hex = StringBuilder()
	val ascii = StringBuilder()
	val itemsPerLine = (charsPerLine - 1) / 4
	val len = bytes.size
	var i = 0
	while (true) {
		val ord = bytes[i]
		hex.append(String.format("%02X ", ord))
		ascii.append(if (ord > 31) ord.toInt().toChar() else " ")
		++i
		val posInLine = i % itemsPerLine
		val atEnd = i >= len
		var atLineEnd = posInLine == 0
		if (atEnd && !atLineEnd) {
			for (j in posInLine until itemsPerLine) {
				hex.append("   ")
			}
			atLineEnd = true
		}
		if (atLineEnd) {
			dump.append(hex.toString())
			dump.append(" ")
			dump.append(ascii.toString())
			dump.append("\n")
			hex.setLength(0)
			ascii.setLength(0)
		}
		if (atEnd) {
			break
		}
	}
	return dump.toString()
}
