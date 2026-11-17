/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.components;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.ComponentUtil;
import com.vaadin.flow.component.UI;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.Objects.requireNonNull;

/**
 * Remembers, per {@link UI}, every component whose visibility or enabled-state follows a
 * security requirement, so that all of them can be evaluated again at once (R8, JS-SEC-167,
 * CWE-613).
 * <p>
 * The secured components evaluate their requirement when they are built and when they are
 * attached. A view that stays open while the subject's roles change kept showing the controls
 * of the old roles until the next navigation. {@link #refreshAll(UI)} - documented entry
 * point {@link SecuredVisibility#refreshAll(UI)} - evaluates every binding of a UI again:
 * {@link SecuredButton}, {@link SecuredRouterLink}, {@link SecuredMenuItem}, and the starter's
 * {@code SecuredUi} builders ({@code component(...)}, {@code action(...)}, the
 * {@code requiresPolicy(...)} variants). The Vaadin adapter's
 * {@code VaadinJCustosVersionChangeBridge} calls it when the subject's security version
 * changes and the session stays open.
 * <p>
 * <strong>Memory.</strong> A UI holds its registry as component data; the registry holds the
 * components weakly. A component that is no longer referenced from anywhere else is dropped
 * the next time the registry is read, and nothing here keeps a closed UI alive. The refresh
 * action of a binding is stored on its component, so it lives exactly as long as the component.
 * <p>
 * <strong>Which UI.</strong> A component is registered with the UI it is attached to - when it
 * is registered, and again on every attach. A component that is not attached yet is
 * registered with the current UI of the thread, if there is one: views build their components
 * while their UI is current. A component that turns up in another UI is dropped from the
 * first one by the next {@link #refreshAll(UI)}.
 * <p>
 * <strong>Locking.</strong> Like every change to a component, {@link #refreshAll(UI)} needs the
 * session lock of the UI: call it from a listener, a navigation observer or inside
 * {@code ui.access(...)}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class SecuredBindingRegistry {

  private SecuredBindingRegistry() {
    // utility
  }

  /**
   * Registers a binding: {@code refresh} applies the requirement of {@code component} again.
   * The registry does not run it now - the caller evaluated the requirement already - and
   * does not run it on attach; it runs it from {@link #refreshAll(UI)}. A component may carry
   * several bindings; each is refreshed.
   *
   * @param component the secured component; non-null
   * @param refresh   evaluates the requirement and applies the result to the component;
   *                  non-null. It is stored on the component, so it may refer to it
   */
  public static void register(Component component, Runnable refresh) {
    requireNonNull(component, "component must not be null");
    requireNonNull(refresh, "refresh must not be null");
    Bindings bindings = ComponentUtil.getData(component, Bindings.class);
    if (bindings == null) {
      bindings = new Bindings();
      ComponentUtil.setData(component, Bindings.class, bindings);
      component.addAttachListener(attach -> track(attach.getUI(), attach.getSource()));
    }
    bindings.refreshers.add(refresh);
    UI ui = component.getUI().orElseGet(UI::getCurrent);
    if (ui != null) {
      track(ui, component);
    }
  }

  /**
   * Evaluates every binding registered with {@code ui} again and drops the components that
   * were garbage-collected or now belong to another UI. A refresh that throws is logged with
   * the class of the component and of the exception, and the component is hidden: a binding
   * that cannot be evaluated does not show its control (fail closed). Call it with the session
   * lock of {@code ui} held.
   *
   * @param ui the UI whose bindings are refreshed; non-null
   * @return the number of components that were refreshed
   */
  public static int refreshAll(UI ui) {
    requireNonNull(ui, "ui must not be null");
    Tracked tracked = ComponentUtil.getData(ui, Tracked.class);
    if (tracked == null) {
      return 0;
    }
    int refreshed = 0;
    for (Component component : tracked.snapshot()) {
      Optional<UI> owner = component.getUI();
      if (owner.isPresent() && owner.get() != ui) {
        tracked.remove(component);
        continue;
      }
      Bindings bindings = ComponentUtil.getData(component, Bindings.class);
      if (bindings == null) {
        tracked.remove(component);
        continue;
      }
      refresh(component, bindings);
      refreshed++;
    }
    return refreshed;
  }

  /**
   * @param ui the UI; non-null
   * @return the number of live components registered with {@code ui}
   */
  public static int registeredCount(UI ui) {
    requireNonNull(ui, "ui must not be null");
    Tracked tracked = ComponentUtil.getData(ui, Tracked.class);
    return tracked == null ? 0 : tracked.snapshot().size();
  }

  private static void refresh(Component component, Bindings bindings) {
    for (Runnable refresher : bindings.refreshers) {
      try {
        refresher.run();
      } catch (RuntimeException refreshFailure) {
        // fail closed: a control whose requirement cannot be evaluated is not shown
        HasLogger.staticLogger().warn("Refreshing the secured binding of a {} failed with {}; "
                + "the component is hidden", component.getClass().getName(),
            refreshFailure.getClass().getName());
        component.setVisible(false);
      }
    }
  }

  private static void track(UI ui, Component component) {
    Tracked tracked = ComponentUtil.getData(ui, Tracked.class);
    if (tracked == null) {
      tracked = new Tracked();
      ComponentUtil.setData(ui, Tracked.class, tracked);
    }
    tracked.add(component);
  }

  /** The refresh actions of one component; stored on the component itself. */
  private static final class Bindings {
    private final List<Runnable> refreshers = new CopyOnWriteArrayList<>();
  }

  /** The components registered with one UI; weak, so the registry never keeps one alive. */
  private static final class Tracked {
    private final Set<Component> components =
        Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

    void add(Component component) {
      components.add(component);
    }

    void remove(Component component) {
      components.remove(component);
    }

    List<Component> snapshot() {
      synchronized (components) {
        return new ArrayList<>(components);
      }
    }
  }
}
