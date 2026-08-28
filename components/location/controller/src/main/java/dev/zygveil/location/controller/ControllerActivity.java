// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import android.app.Activity;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.IOException;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class ControllerActivity extends Activity {
  public static final String ACTION_REQUEST_ROOT =
      "dev.zygveil.location.controller.action.REQUEST_ROOT";

  private final ExecutorService executor = Executors.newSingleThreadExecutor();
  private final List<PresetCodec.Preset> presets = new ArrayList<>();
  private final OperationGuard operationGuard = new OperationGuard();
  private Future<?> currentOperation;
  private PresetStore presetStore;
  private EditText latitude;
  private EditText longitude;
  private EditText altitudeEllipsoid;
  private EditText altitudeMsl;
  private EditText presetName;
  private Button apply;
  private ImageButton refresh;
  private ImageButton savePreset;
  private TextView statusValue;
  private TextView statusDetails;
  private LinearLayout statusBand;
  private LinearLayout presetList;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    presetStore = new PresetStore(getNoBackupFilesDir());
    setContentView(createContent());
    loadPresets();
    handleAction(getIntent());
  }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    handleAction(intent);
  }

  @Override
  protected void onDestroy() {
    operationGuard.invalidate();
    if (currentOperation != null) {
      currentOperation.cancel(true);
    }
    executor.shutdownNow();
    super.onDestroy();
  }

  private View createContent() {
    ScrollView scroll = new ScrollView(this);
    scroll.setBackgroundColor(getColor(R.color.canvas));
    scroll.setFillViewport(true);
    scroll.setFitsSystemWindows(true);

    LinearLayout content = new LinearLayout(this);
    content.setOrientation(LinearLayout.VERTICAL);
    content.setPadding(dp(20), dp(20), dp(20), dp(32));
    content.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
    scroll.addView(
        content,
        new ScrollView.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

    LinearLayout header = horizontal();
    TextView title = text(R.string.app_name, 24, R.color.ink);
    title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
    header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
    refresh = iconButton(android.R.drawable.ic_popup_sync, R.string.refresh);
    refresh.setOnClickListener(view -> execute(RootHelper.Flow.STATUS_UI, null, true));
    header.addView(refresh, square(48));
    content.addView(header, fullWidth());

    addSpacer(content, 16);
    content.addView(
        divider(), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
    addSpacer(content, 20);

    content.addView(sectionTitle(R.string.status), fullWidth());
    addSpacer(content, 8);
    statusBand = new LinearLayout(this);
    statusBand.setOrientation(LinearLayout.VERTICAL);
    statusBand.setPadding(dp(16), dp(14), dp(16), dp(14));
    statusValue = text(R.string.status_idle, 18, R.color.ink);
    statusValue.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
    statusBand.addView(statusValue, fullWidth());
    statusDetails = text(null, 14, R.color.muted);
    statusDetails.setTextIsSelectable(false);
    statusDetails.setVisibility(View.GONE);
    statusBand.addView(statusDetails, fullWidth());
    content.addView(statusBand, fullWidth());
    showState(new ControllerState(ControllerState.Tone.IDLE, "none"), null);

    addSpacer(content, 28);
    content.addView(sectionTitle(R.string.coordinates), fullWidth());
    addSpacer(content, 6);
    latitude = addCoordinateField(content, R.string.latitude, "0");
    longitude = addCoordinateField(content, R.string.longitude, "0");
    altitudeEllipsoid = addCoordinateField(content, R.string.altitude_ellipsoid, "0");
    altitudeMsl = addCoordinateField(content, R.string.altitude_msl, "0");

    addSpacer(content, 12);
    apply = new Button(this);
    apply.setText(R.string.apply);
    apply.setAllCaps(false);
    apply.setTextSize(16);
    apply.setTextColor(Color.WHITE);
    apply.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_send, 0, 0, 0);
    apply.setCompoundDrawablePadding(dp(8));
    apply.setBackgroundTintList(ColorStateList.valueOf(getColor(R.color.accent)));
    apply.setMinHeight(dp(52));
    apply.setOnClickListener(view -> applyCoordinates());
    content.addView(apply, fullWidth());

    addSpacer(content, 28);
    content.addView(sectionTitle(R.string.presets), fullWidth());
    addSpacer(content, 8);
    LinearLayout saveRow = horizontal();
    presetName = new EditText(this);
    presetName.setHint(R.string.preset_name);
    presetName.setSingleLine(true);
    presetName.setSaveEnabled(false);
    presetName.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
    presetName.setFilters(new InputFilter[] {new InputFilter.LengthFilter(32)});
    saveRow.addView(presetName, new LinearLayout.LayoutParams(0, dp(52), 1));
    savePreset = iconButton(android.R.drawable.ic_menu_save, R.string.save_preset);
    savePreset.setOnClickListener(view -> savePreset());
    LinearLayout.LayoutParams saveButtonParameters = square(52);
    saveButtonParameters.setMarginStart(dp(8));
    saveRow.addView(savePreset, saveButtonParameters);
    content.addView(saveRow, fullWidth());

    presetList = new LinearLayout(this);
    presetList.setOrientation(LinearLayout.VERTICAL);
    content.addView(presetList, fullWidth());
    return scroll;
  }

  private void handleAction(Intent intent) {
    String action = intent == null ? null : intent.getAction();
    if (ACTION_REQUEST_ROOT.equals(action)) {
      execute(RootHelper.Flow.STATUS, null, false);
    } else if (Intent.ACTION_MAIN.equals(action)) {
      execute(RootHelper.Flow.STATUS_UI, null, true);
    }
  }

  private EditText addCoordinateField(LinearLayout parent, int labelResource, String initial) {
    TextView label = text(labelResource, 14, R.color.muted);
    LinearLayout.LayoutParams labelParameters = fullWidth();
    labelParameters.topMargin = dp(10);
    parent.addView(label, labelParameters);
    EditText field = new EditText(this);
    field.setId(View.generateViewId());
    label.setLabelFor(field.getId());
    field.setSingleLine(true);
    field.setSaveEnabled(false);
    field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
    field.setSelectAllOnFocus(true);
    field.setText(initial);
    field.setTextColor(getColor(R.color.ink));
    field.setTextSize(17);
    field.setInputType(
        InputType.TYPE_CLASS_NUMBER
            | InputType.TYPE_NUMBER_FLAG_DECIMAL
            | InputType.TYPE_NUMBER_FLAG_SIGNED);
    field.setFilters(new InputFilter[] {new InputFilter.LengthFilter(32)});
    field.setMinHeight(dp(48));
    parent.addView(field, fullWidth());
    return field;
  }

  private void applyCoordinates() {
    CoordinateInput.Values values = readCoordinates();
    if (values != null) {
      execute(RootHelper.Flow.APPLY, values.toHelperInput(), false);
    }
  }

  private CoordinateInput.Values readCoordinates() {
    clearCoordinateErrors();
    Locale locale = getResources().getConfiguration().getLocales().get(0);
    char separator = DecimalFormatSymbols.getInstance(locale).getDecimalSeparator();
    try {
      return CoordinateInput.parse(
          latitude.getText().toString(),
          longitude.getText().toString(),
          altitudeEllipsoid.getText().toString(),
          altitudeMsl.getText().toString(),
          separator);
    } catch (CoordinateInput.InvalidInput error) {
      EditText field = fieldFor(error.field());
      field.setError(getString(errorResource(error)));
      field.requestFocus();
      return null;
    }
  }

  private EditText fieldFor(CoordinateInput.Field field) {
    return switch (field) {
      case LATITUDE -> latitude;
      case LONGITUDE -> longitude;
      case ALTITUDE_ELLIPSOID -> altitudeEllipsoid;
      case ALTITUDE_MSL -> altitudeMsl;
    };
  }

  private int errorResource(CoordinateInput.InvalidInput error) {
    if (error.error() == CoordinateInput.Error.REQUIRED) {
      return R.string.error_required;
    }
    if (error.error() == CoordinateInput.Error.DECIMAL) {
      return R.string.error_decimal;
    }
    if (error.error() == CoordinateInput.Error.PRECISION) {
      return error.field() == CoordinateInput.Field.LATITUDE
              || error.field() == CoordinateInput.Field.LONGITUDE
          ? R.string.error_precision_coordinate
          : R.string.error_precision_altitude;
    }
    return switch (error.field()) {
      case LATITUDE -> R.string.error_latitude_range;
      case LONGITUDE -> R.string.error_longitude_range;
      case ALTITUDE_ELLIPSOID, ALTITUDE_MSL -> R.string.error_altitude_range;
    };
  }

  private void clearCoordinateErrors() {
    latitude.setError(null);
    longitude.setError(null);
    altitudeEllipsoid.setError(null);
    altitudeMsl.setError(null);
  }

  private void execute(RootHelper.Flow flow, String input, boolean loadCoordinates) {
    if (currentOperation != null && !currentOperation.isDone()) {
      currentOperation.cancel(true);
    }
    setBusy(true);
    showState(new ControllerState(ControllerState.Tone.LOADING, "none"), null);
    long operation = operationGuard.begin();
    currentOperation =
        executor.submit(
            () -> {
              RootHelper.Result result = RootHelper.call(flow, input);
              if (flow == RootHelper.Flow.STATUS && operationGuard.isCurrent(operation)) {
                try {
                  RootStatusStore.write(getNoBackupFilesDir(), result);
                } catch (IOException error) {
                  result = RootHelper.Result.failed(RootHelper.Failure.IO);
                }
              }
              RootHelper.Result finalResult = result;
              runOnUiThread(
                  () -> {
                    if (!operationGuard.isCurrent(operation) || isDestroyed()) {
                      return;
                    }
                    setBusy(false);
                    HelperStatus helperStatus = finalResult.status();
                    ControllerState state =
                        finalResult.failure() == RootHelper.Failure.NONE && helperStatus != null
                            ? ControllerState.fromStatus(helperStatus)
                            : ControllerState.fromFailure(finalResult.failure());
                    showState(state, helperStatus);
                    if (loadCoordinates
                        && finalResult.failure() == RootHelper.Failure.NONE
                        && helperStatus != null
                        && helperStatus.coordinates() != null) {
                      setCoordinates(helperStatus.coordinates());
                    }
                  });
            });
  }

  private void showState(ControllerState state, HelperStatus helperStatus) {
    int titleResource;
    int foreground;
    int background;
    switch (state.tone()) {
      case IDLE -> {
        titleResource = R.string.status_idle;
        foreground = R.color.muted;
        background = R.color.surface;
      }
      case LOADING -> {
        titleResource = R.string.status_loading;
        foreground = R.color.muted;
        background = R.color.surface;
      }
      case APPLIED -> {
        titleResource = R.string.status_applied;
        foreground = R.color.accent;
        background = R.color.accent_soft;
      }
      case PENDING_UPSTREAM -> {
        titleResource = R.string.status_pending_upstream;
        foreground = R.color.pending;
        background = R.color.pending_soft;
      }
      case PENDING_REBOOT -> {
        titleResource = R.string.status_pending_reboot;
        foreground = R.color.pending;
        background = R.color.pending_soft;
      }
      case RECOVERY_REQUIRED -> {
        titleResource = R.string.status_recovery_required;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case REJECTED -> {
        titleResource = R.string.status_rejected;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case WAITING -> {
        titleResource = R.string.status_waiting;
        foreground = R.color.accent;
        background = R.color.accent_soft;
      }
      case INACTIVE -> {
        titleResource = R.string.status_inactive;
        foreground = R.color.pending;
        background = R.color.pending_soft;
      }
      case DENIED -> {
        titleResource = R.string.status_denied;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case MISSING -> {
        titleResource = R.string.status_missing;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case TIMEOUT -> {
        titleResource = R.string.status_timeout;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case PROTOCOL -> {
        titleResource = R.string.status_protocol;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      case CANCELLED -> {
        titleResource = R.string.status_cancelled;
        foreground = R.color.muted;
        background = R.color.surface;
      }
      case IO -> {
        titleResource = R.string.status_io;
        foreground = R.color.danger;
        background = R.color.danger_soft;
      }
      default -> throw new IllegalStateException("unhandled_controller_state");
    }
    statusValue.setText(titleResource);
    statusValue.setTextColor(getColor(foreground));
    GradientDrawable shape = new GradientDrawable();
    shape.setColor(getColor(background));
    shape.setCornerRadius(dp(6));
    shape.setStroke(dp(1), getColor(R.color.divider));
    statusBand.setBackground(shape);
    if (helperStatus == null) {
      statusDetails.setVisibility(View.GONE);
      statusDetails.setText(null);
      return;
    }
    String details =
        getString(
            R.string.status_generations,
            helperStatus.bootGeneration(),
            helperStatus.persistedGeneration(),
            helperStatus.publishedGeneration(),
            helperStatus.appliedGeneration());
    if (!"none".equals(state.reason())) {
      details += "\n" + getString(R.string.status_reason, state.reason().replace('_', ' '));
    }
    statusDetails.setText(details);
    statusDetails.setVisibility(View.VISIBLE);
  }

  private void setCoordinates(CoordinateInput.Values values) {
    latitude.setText(values.latitude());
    longitude.setText(values.longitude());
    altitudeEllipsoid.setText(values.altitudeEllipsoid());
    altitudeMsl.setText(values.altitudeMsl());
  }

  private void setBusy(boolean busy) {
    apply.setEnabled(!busy);
    refresh.setEnabled(!busy);
    savePreset.setEnabled(!busy);
  }

  private void loadPresets() {
    try {
      presets.clear();
      presets.addAll(presetStore.load());
      renderPresets();
    } catch (PresetStore.StoreException error) {
      presets.clear();
      renderPresets();
      presetName.setError(getString(R.string.error_preset_store));
    }
  }

  private void savePreset() {
    presetName.setError(null);
    CoordinateInput.Values values = readCoordinates();
    if (values == null) {
      return;
    }
    String name = presetName.getText().toString();
    final PresetCodec.Preset preset;
    try {
      preset = PresetCodec.create(name, values);
    } catch (PresetCodec.CodecException error) {
      presetName.setError(getString(R.string.error_preset_name));
      return;
    }
    int existing = -1;
    for (int index = 0; index < presets.size(); index++) {
      if (presets.get(index).name().equals(preset.name())) {
        existing = index;
        break;
      }
    }
    List<PresetCodec.Preset> updated = new ArrayList<>(presets);
    if (existing >= 0) {
      updated.set(existing, preset);
    } else if (updated.size() < PresetCodec.MAXIMUM_PRESETS) {
      updated.add(preset);
    } else {
      presetName.setError(getString(R.string.error_preset_limit));
      return;
    }
    persistPresets(updated);
  }

  private void deletePreset(int index) {
    if (index >= 0 && index < presets.size()) {
      List<PresetCodec.Preset> updated = new ArrayList<>(presets);
      updated.remove(index);
      persistPresets(updated);
    }
  }

  private void persistPresets(List<PresetCodec.Preset> updated) {
    try {
      presetStore.save(updated);
      presets.clear();
      presets.addAll(updated);
      presetName.setText(null);
      renderPresets();
    } catch (PresetStore.StoreException error) {
      presetName.setError(getString(R.string.error_preset_store));
    }
  }

  private void renderPresets() {
    presetList.removeAllViews();
    if (presets.isEmpty()) {
      TextView empty = text(R.string.presets_empty, 14, R.color.muted);
      empty.setPadding(0, dp(14), 0, dp(8));
      presetList.addView(empty, fullWidth());
      return;
    }
    for (int index = 0; index < presets.size(); index++) {
      int presetIndex = index;
      PresetCodec.Preset preset = presets.get(index);
      LinearLayout row = horizontal();
      row.setGravity(Gravity.CENTER_VERTICAL);
      row.setPadding(0, dp(6), 0, dp(6));
      Button load = new Button(this);
      load.setText(preset.name());
      load.setContentDescription(getString(R.string.load_preset, preset.name()));
      load.setAllCaps(false);
      load.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
      load.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_set_as, 0, 0, 0);
      load.setCompoundDrawablePadding(dp(8));
      load.setOnClickListener(view -> setCoordinates(preset.values()));
      row.addView(load, new LinearLayout.LayoutParams(0, dp(52), 1));
      ImageButton delete = iconButton(android.R.drawable.ic_menu_delete, R.string.delete_preset);
      delete.setContentDescription(getString(R.string.delete_preset, preset.name()));
      delete.setOnClickListener(view -> deletePreset(presetIndex));
      LinearLayout.LayoutParams deleteParameters = square(52);
      deleteParameters.setMarginStart(dp(8));
      row.addView(delete, deleteParameters);
      presetList.addView(row, fullWidth());
    }
  }

  private TextView sectionTitle(int resource) {
    TextView view = text(resource, 18, R.color.ink);
    view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
    return view;
  }

  private TextView text(Integer resource, int size, int color) {
    TextView view = new TextView(this);
    if (resource != null) {
      view.setText(resource);
    }
    view.setTextSize(size);
    view.setTextColor(getColor(color));
    view.setGravity(Gravity.START);
    return view;
  }

  private ImageButton iconButton(int icon, int description) {
    ImageButton button = new ImageButton(this);
    button.setImageResource(icon);
    button.setImageTintList(ColorStateList.valueOf(getColor(R.color.ink)));
    button.setContentDescription(getString(description));
    button.setPadding(dp(12), dp(12), dp(12), dp(12));
    TypedValue background = new TypedValue();
    if (getTheme()
        .resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, background, true)) {
      button.setBackgroundResource(background.resourceId);
    } else {
      button.setBackgroundColor(Color.TRANSPARENT);
    }
    return button;
  }

  private LinearLayout horizontal() {
    LinearLayout layout = new LinearLayout(this);
    layout.setOrientation(LinearLayout.HORIZONTAL);
    layout.setGravity(Gravity.CENTER_VERTICAL);
    return layout;
  }

  private View divider() {
    View view = new View(this);
    view.setBackgroundColor(getColor(R.color.divider));
    return view;
  }

  private void addSpacer(LinearLayout parent, int height) {
    parent.addView(new View(this), new LinearLayout.LayoutParams(1, dp(height)));
  }

  private LinearLayout.LayoutParams fullWidth() {
    return new LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
  }

  private LinearLayout.LayoutParams square(int size) {
    return new LinearLayout.LayoutParams(dp(size), dp(size));
  }

  private int dp(int value) {
    return Math.round(
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
  }
}
