/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.starter.errors;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.router.HasErrorParameter;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.internal.ErrorTargetEntry;
import com.vaadin.flow.server.DefaultErrorHandler;
import com.vaadin.flow.server.ErrorEvent;
import com.vaadin.flow.server.ErrorHandler;
import com.vaadin.flow.server.ErrorHandlerUtil;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.startup.ApplicationRouteRegistry;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A session {@link ErrorHandler} that shows the user a reference instead of the exception
 * and logs the stack trace under that reference (JS-SEC-067, CWE-209).
 * <p>
 * An error that escapes application code - a click listener, a value-change listener, a
 * {@code UI.access} command - reaches the session's error handler. Applications that replace
 * Vaadin's {@link DefaultErrorHandler} with their own commonly lose two things: the
 * forwarding to a {@link HasErrorParameter} view, and the separation between what the log
 * receives and what the user sees; a handler that puts {@code throwable.getMessage()} into a
 * notification hands SQL, file paths, subject ids and credentials to the browser. This
 * handler keeps both:
 * <ol>
 *   <li>It asks {@link ErrorHandlerUtil#handleErrorByRedirectingToErrorView(Throwable)} first,
 *       as Vaadin's default does. When an error view is registered for exactly the class of
 *       the throwable - a {@code HasErrorParameter<AccessDeniedException>} for the
 *       {@link AccessDeniedException} a secured service throws, for example - that view is
 *       shown and the handler is done. Not so for Vaadin's own {@link InternalServerError},
 *       which Vaadin registers for {@code java.lang.Exception}: it writes the root cause of
 *       the exception into the page, so a plain {@code Exception} - a sneaky throw, Kotlin
 *       code, an application-built {@link ErrorEvent} - takes the reference path below like
 *       every other error (exit review RF15, CWE-209). The same holds for a subclass of it.</li>
 *   <li>Otherwise it draws a reference of {@value #REFERENCE_LENGTH} Base32 characters from
 *       {@link SecureRandom} and logs {@code "Unhandled error, reference {}"} at ERROR with
 *       the throwable. The message format carries nothing but the reference; the stack trace
 *       - including the exception's own message - goes to the log only.</li>
 *   <li>The user sees a {@link Notification} with the reference and nothing else of the
 *       error: the translation of {@value #MESSAGE_KEY} with the reference as {@code {0}}, or
 *       {@value #FALLBACK_MESSAGE} when there is no translation. A translation that does not
 *       contain the reference is ignored, since the reference is what support needs.</li>
 * </ol>
 * Errors that only say the client went away ({@link DefaultErrorHandler#SOCKET_EXCEPTIONS})
 * are logged at DEBUG and not shown, as Vaadin's default handler ignores them. Without a
 * {@link UI} bound to the thread the error is logged with its reference and nothing is
 * shown.
 * <p>
 * <strong>Failures inside the handler</strong> never leave it: a failing error view, a
 * failing translation or a failing notification is logged, and an error raised while the
 * handler is running on the same thread - by the notification, say - is logged with its own
 * reference and not shown, so the handler cannot recurse.
 * <p>
 * <strong>Installation</strong> is opt-in: call {@link #install(ServiceInitEvent)} from the
 * application's {@link VaadinServiceInitListener}. Every Vaadin session created afterwards
 * gets the handler:
 * <pre>{@code
 *   public final class AppServiceInitListener implements VaadinServiceInitListener {
 *     public void serviceInit(ServiceInitEvent event) {
 *       JCustosErrorHandler.install(event);
 *     }
 *   }
 * }</pre>
 * A subclass that shows the reference differently - in a dialog, with a support address -
 * overrides {@link #showReference(UI, String)} and is set per session the same way:
 * {@code event.getSource().addSessionInitListener(e -> e.getSession().setErrorHandler(new
 * MyErrorHandler()))}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public class JCustosErrorHandler implements ErrorHandler, HasLogger {

  /** Translation key of the notification text; the reference is parameter {@code {0}}. */
  public static final String MESSAGE_KEY = "jcustos.error.reference";

  /** Notification text when {@value #MESSAGE_KEY} has no usable translation. */
  public static final String FALLBACK_MESSAGE =
      "An unexpected error occurred. Please quote reference {0} when you report it.";

  /** Length of the reference in Base32 characters: 80 random bits. */
  public static final int REFERENCE_LENGTH = 16;

  /** How long the notification stays open, in milliseconds; default 15 seconds. */
  public static final int NOTIFICATION_DURATION_MILLIS = 15_000;

  /** Element id of the notification, for tests and styling. */
  public static final String NOTIFICATION_ID = "jcustos-error-reference";

  @Serial
  private static final long serialVersionUID = 1L;

  /** RFC 4648 Base32 alphabet: no lower case, no 0, 1, 8 or 9 to misread. */
  private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  private static final SecureRandom RANDOM = new SecureRandom();

  /** Set while this thread is inside {@link #error(ErrorEvent)}: the re-entry guard. */
  private static final ThreadLocal<Boolean> HANDLING = new ThreadLocal<>();

  /** Creates a handler; it has no state of its own. */
  public JCustosErrorHandler() {
  }

  /**
   * Registers a {@code SessionInitListener} that sets a new {@code JCustosErrorHandler} on
   * every Vaadin session the service creates from now on.
   *
   * @param event the service-init event of the application's {@code VaadinServiceInitListener}
   * @return the registration of the session-init listener
   */
  public static Registration install(ServiceInitEvent event) {
    requireNonNull(event, "event must not be null");
    return event.getSource().addSessionInitListener(
        sessionInit -> sessionInit.getSession().setErrorHandler(new JCustosErrorHandler()));
  }

  @Override
  public void error(ErrorEvent event) {
    Throwable throwable = event == null ? null : event.getThrowable();
    if (HANDLING.get() != null) {
      // raised while this thread is reporting another error - log it, never show or recurse
      logger().error("Unhandled error while another error was being reported, reference {}",
          newReference(), throwable);
      return;
    }
    HANDLING.set(Boolean.TRUE);
    try {
      handle(throwable);
    } catch (RuntimeException handlerFailure) {
      logger().error("The error handler failed while reporting an error", handlerFailure);
    } finally {
      HANDLING.remove();
    }
  }

  /**
   * Shows {@code reference} to the user: a notification with the translation of
   * {@value #MESSAGE_KEY}, else {@value #FALLBACK_MESSAGE}. Called with {@code ui} bound to
   * the thread; whatever this method throws is logged by the handler.
   *
   * @param ui        the current UI
   * @param reference the reference the error is logged under
   */
  protected void showReference(UI ui, String reference) {
    Notification notification = new Notification(referenceText(ui, reference),
        NOTIFICATION_DURATION_MILLIS);
    notification.setId(NOTIFICATION_ID);
    notification.addThemeVariants(NotificationVariant.ERROR);
    notification.open();
  }

  private void handle(Throwable throwable) {
    if (throwable != null
        && DefaultErrorHandler.SOCKET_EXCEPTIONS.contains(throwable.getClass().getName())) {
      logger().debug("The client went away ({}); nothing to report", throwable.getClass().getName());
      return;
    }
    if (redirectedToErrorView(throwable)) {
      return;
    }
    String reference = newReference();
    logger().error("Unhandled error, reference {}", reference, throwable);
    UI ui = UI.getCurrent();
    if (ui == null) {
      logger().debug("No UI is bound to the thread; reference {} is not shown", reference);
      return;
    }
    showReference(ui, reference);
  }

  private boolean redirectedToErrorView(Throwable throwable) {
    try {
      if (wouldShowInternalServerError(throwable)) {
        return false;
      }
      return ErrorHandlerUtil.handleErrorByRedirectingToErrorView(throwable);
    } catch (RuntimeException redirectFailure) {
      logger().warn("The error view for {} could not be shown ({}); the error is reported with a "
          + "reference instead", throwable.getClass().getName(), redirectFailure.getClass().getName());
      return false;
    }
  }

  /**
   * RF15 (CWE-209): whether {@link ErrorHandlerUtil} would show {@link InternalServerError} -
   * or a subclass that inherits its rendering - for {@code throwable}. It redirects when the
   * error view registered for the throwable's exact class is found, and Vaadin registers
   * {@code InternalServerError} for {@code java.lang.Exception}; that view prints the root
   * cause, with the stack trace outside production mode. Looked up the way
   * {@code ErrorHandlerUtil} looks it up.
   */
  private static boolean wouldShowInternalServerError(Throwable throwable) {
    if (!(throwable instanceof Exception exception)) {
      return false;
    }
    UI ui = UI.getCurrent();
    VaadinSession session = ui == null ? null : ui.getSession();
    VaadinService service = session == null ? null : session.getService();
    if (service == null || service.getContext() == null) {
      return false; // ErrorHandlerUtil redirects to nothing without them either
    }
    Optional<ErrorTargetEntry> target = ApplicationRouteRegistry.getInstance(service.getContext())
        .getErrorNavigationTarget(exception);
    return target.isPresent()
        && target.get().getHandledExceptionType().equals(exception.getClass())
        && InternalServerError.class.isAssignableFrom(target.get().getNavigationTarget());
  }

  private String referenceText(UI ui, String reference) {
    try {
      String translated = ui.getTranslation(MESSAGE_KEY, reference);
      // a miss comes back as the key ("!{key}!", "!en: key", "key"); a text without the
      // reference would leave the user nothing to quote
      if (translated != null && translated.contains(reference)
          && !translated.contains(MESSAGE_KEY)) {
        return translated;
      }
    } catch (RuntimeException translationFailure) {
      logger().debug("The translation of {} failed ({}); the English text is shown", MESSAGE_KEY,
          translationFailure.getClass().getName());
    }
    return MessageFormat.format(FALLBACK_MESSAGE, reference);
  }

  /** @return a fresh reference of {@value #REFERENCE_LENGTH} Base32 characters */
  static String newReference() {
    char[] reference = new char[REFERENCE_LENGTH];
    for (int i = 0; i < reference.length; i++) {
      reference[i] = BASE32_ALPHABET.charAt(RANDOM.nextInt(BASE32_ALPHABET.length()));
    }
    return new String(reference);
  }
}
