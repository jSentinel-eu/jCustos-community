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
package eu.jsentinel.jcustos.processor;

import com.squareup.javapoet.ArrayTypeName;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import com.squareup.javapoet.WildcardTypeName;
import com.svenruppert.proxybuilder.annotations.ProxyBuilderOptions;
import com.svenruppert.proxybuilder.annotations.SkipProxy;
import com.svenruppert.proxybuilder.proxy.generated.BasicStaticProxyAnnotationProcessor;
import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.annotations.Secured;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;

import javax.annotation.processing.FilerException;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Generates a {@code <Type>Secured} wrapper subclass for each
 * {@link Secured @Secured}-annotated concrete class. The wrapper
 * inherits from the original, overrides every public, non-final,
 * non-static method, and inserts a
 * {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer JCustosEnforcer}
 * pre-check ahead of the {@code super.<method>(...)} delegate of
 * <em>every</em> overridden method.
 *
 * <p>Five annotations are lowered natively, into a call of the explicit
 * enforcer API:
 * <ul>
 *   <li>{@link RequiresPermission} (1 value)  →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requirePermission(String)}</li>
 *   <li>{@link RequiresPermission} (n values) →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAllPermissions} →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requireAllPermissions(String...)}</li>
 *   <li>{@link RequiresAnyPermission} →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requireAnyPermission(String...)}</li>
 *   <li>{@link RequiresRole} (1 value)  →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requireRole(String)}</li>
 *   <li>{@link RequiresRole} (n values) →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requireAnyRole(String...)}</li>
 *   <li>{@link RequiresPolicy} →
 *       {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#requirePolicy(String)}</li>
 * </ul>
 *
 * <p><strong>JS-SEC-156 (CWE-862, CWE-1068).</strong> Everything the
 * native mapping does not cover is routed through the generic
 * {@link eu.jsentinel.jcustos.authorization.api.JCustosEnforcer#enforce(java.lang.reflect.Method, Class)
 * JCustosEnforcer.enforce(Method, Class)} - the very call the run-time
 * sibling {@code SecuredProxy} makes - so that both paths decide alike:
 * <ul>
 *   <li>a restriction annotation without a native mapping:
 *       {@link eu.jsentinel.jcustos.authorization.annotations.ProtectedBy @ProtectedBy}
 *       and any consumer-defined annotation that is meta-annotated with
 *       {@link JCustosAnnotation @JCustosAnnotation};</li>
 *   <li>a restriction the processor cannot pin down at compile time: one
 *       inherited from a superclass or an interface, one that applies
 *       to a method declared in a supertype, one written on a supertype
 *       declaration the method overrides or implements without repeating it
 *       (JS-SEC-159), and a composed restriction - an annotation whose type
 *       carries the restriction (JS-SEC-154);</li>
 *   <li>a method without any restriction - the call is a no-op under
 *       allow-by-omission and denies under deny-by-default (JS-SEC-081)
 *       unless the method or its class carries
 *       {@link PublicRoute @PublicRoute}.</li>
 * </ul>
 * The wrapper resolves the {@link java.lang.reflect.Method} once, in a
 * static field of the generated class; a method that cannot be resolved
 * fails the class initialisation with an {@link IllegalStateException}
 * instead of leaving the call unguarded.
 *
 * <p><strong>JS-SEC-159 (CWE-862).</strong> A restriction on an interface or
 * superclass method that the {@code @Secured} class overrides without
 * repeating it is enforced through that generic call: the run-time scanner
 * looks for it after the class-level restriction (JS-SEC-114), and the
 * wrapper hands the overriding method and the {@code @Secured} class to the
 * same enforcer. {@code SecuredWrapperParityTest} pins wrapper and
 * {@code SecuredProxy} to the same decision for these cases. The run-time
 * scanner is the reference: a class-level restriction of the
 * {@code @Secured} class, declared or inherited, takes precedence over the
 * restriction of the overridden declaration, and {@link PublicRoute @PublicRoute}
 * on the overriding method is the opt-out.
 *
 * <p>Method-level annotations take precedence over class-level
 * annotations (one enforcer call per generated method). At most one
 * restriction annotation may appear on any single element — more than
 * one raises a {@code processing/multiple-security-annotations} compile
 * error (R031), matching the runtime scanner contract.
 *
 * <p>A restriction annotation on a method the wrapper does not override
 * is a {@code processing/unenforceable-security-annotation} compile
 * error: a {@code final}, {@code static} or {@code private} method, a
 * {@code protected} or package-private one, an {@link Object} method,
 * and a method excluded through {@link SkipProxy @SkipProxy} or
 * {@link ProxyBuilderOptions#excludeMethodNames()}. Before JS-SEC-156
 * such a method was left out of the wrapper without a word. The generic
 * {@code final}/{@code private}/{@code static} diagnostics of the
 * underlying {@code com.svenruppert:proxybuilder} base processor remain
 * in place alongside.
 *
 * <p>Since 00.84.00 the same holds for a restriction the method does not
 * carry itself but that the run-time scanner applies to it: one written
 * on a supertype declaration the method overrides or implements, and -
 * for a public instance method - the class-level restriction of the
 * {@code @Secured} class. The wrapper runs such a method for every caller
 * while {@code SecuredProxy} and {@code JCustosEnforcer.enforce} deny it,
 * so it is a compile error too. A public instance method the wrapper does
 * not override and to which no restriction applies is reported as a
 * {@code processing/deny-by-default-not-applied} warning: deny-by-default
 * cannot cover it. {@link PublicRoute @PublicRoute} on the method is the
 * opt-out for both.
 *
 * <p>Only an annotation that {@link JCustosAnnotation @JCustosAnnotation}
 * binds to an {@link AccessEvaluator} or {@link AuthorizationEvaluator} is a
 * restriction, for the processor as for the run-time scanner. Any other
 * binding - core's {@code @PropagateToken} - is ignored, so it neither
 * guards a method nor keeps deny-by-default from applying. A restriction
 * composed more than one level deep ({@code @AdminOnly @interface
 * SuperAdmin}) is a {@code processing/nested-composed-security-annotation}
 * compile error: the run-time scanner resolves composition one level deep
 * and refuses anything deeper.
 *
 * <p>The generated class carries
 * {@code @GeneratedByProxyBuilder(...)} and
 * {@code @DelegatesTo(...)} from the {@code proxybuilder-annotations}
 * module; consumers of {@code jCustos-processor} pull that module as
 * a regular compile dependency so the markers resolve in their own
 * compile classpath.
 */
public final class SecuredAnnotationProcessor
    extends BasicStaticProxyAnnotationProcessor<Secured> {

  private static final ClassName ENFORCER = ClassName.get(
      "eu.jsentinel.jcustos.authorization.api", "JCustosEnforcer");

  /**
   * The method-security annotations this processor recognises. R031: at most
   * one may appear on a single element, matching the runtime scanner's
   * one-annotation-per-element contract.
   */
  private static final List<Class<? extends Annotation>> SECURITY_ANNOTATIONS = List.of(
      RequiresPermission.class,
      RequiresAllPermissions.class,
      RequiresAnyPermission.class,
      RequiresRole.class,
      RequiresPolicy.class);

  // JS-SEC-156 (CWE-862): diagnostics and generated member names of the generic guard.
  private static final String DIAG_UNENFORCEABLE =
      "processing/unenforceable-security-annotation";
  private static final String DIAG_NO_DENY_BY_DEFAULT =
      "processing/deny-by-default-not-applied";
  private static final String DIAG_NESTED_COMPOSITION =
      "processing/nested-composed-security-annotation";
  private static final String GUARD_FIELD_PREFIX = "JCUSTOS_GUARD_METHOD_";
  private static final String GUARD_RESOLVER = "jcustosGuardMethod";

  // V00.73: wrapper-index writer state. Must stay in sync with the
  // package-private eu.jsentinel.jcustos.dx.diagnostics.WrapperIndexFormat
  // class in jCustos-dx — that module's classes aren't visible here,
  // so the literals are duplicated and the reader matches by value.
  private static final String INDEX_RESOURCE_PATH =
      "META-INF/jcustos/generated-wrappers.idx";
  private static final String INDEX_MARKER_COMMENT =
      "# generated by jCustos-processor";
  private static final String INDEX_FIELD_SEPARATOR = ":";
  private static final String INDEX_METHOD_SEPARATOR = ",";
  private static final String INDEX_PROCESSOR_ID = "proxybuilder";
  // The proxybuilder version in the index is the one of the base processor that
  // generated the wrapper, read from the Maven metadata of its own jar - a literal
  // went stale with every proxybuilder update (it said 00.11.00 next to 00.11.01).
  private static final String PROXYBUILDER_POM_PROPERTIES =
      "META-INF/maven/com.svenruppert/proxybuilder/pom.properties";
  private static final String PROXYBUILDER_VERSION_KEY = "version";
  /** Written when the base processor's Maven metadata cannot be read. */
  static final String UNKNOWN_PROXYBUILDER_VERSION = "unknown";
  private static final String INDEX_PROXYBUILDER_VERSION = proxyBuilderVersion();
  // V00.74: optional sixth field — wrapper kind.
  private static final String INDEX_KIND_SECURED = "secured";

  /**
   * Per-source-FQN list of guarded method names collected during this
   * compilation. Iteration order is alphabetical (TreeMap) so the
   * written file is deterministic across runs.
   */
  private final Map<String, List<String>> indexBySource = new TreeMap<>();

  /** The source FQN currently being processed; set by {@link #addClassLevelSpecs}. */
  private String currentSourceFqn;

  /** Number of guard-method fields added to the wrapper currently being generated. */
  private int guardMethodCount;

  /** Creates the processor. Loaded via {@code META-INF/services}. */
  public SecuredAnnotationProcessor() {
  }

  @Override
  public Class<Secured> responsibleFor() {
    return Secured.class;
  }

  @Override
  public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
    final boolean claimed = super.process(annotations, roundEnv);
    if (roundEnv.processingOver()) {
      writeIndex();
    }
    return claimed;
  }

  @Override
  protected void addClassLevelSpecs(TypeElement typeElement, RoundEnvironment roundEnv) {
    // JCustosEnforcer is a static facade — no instance field or
    // builder method is added to the generated wrapper here (the static
    // guard-method fields of JS-SEC-156 are added per method, on demand).
    // The hook is used to capture the FQN of the class being processed so
    // that index entries can be attributed to it later.
    currentSourceFqn = typeElement.getQualifiedName().toString();
    indexBySource.computeIfAbsent(currentSourceFqn, k -> new ArrayList<>());
    guardMethodCount = 0;
    // R031: a class carrying more than one security annotation is a configuration
    // error — the dropped constraint would otherwise be silently unenforced.
    verifyAtMostOneSecurityAnnotation(typeElement);
    // BL02 (V00.81): an empty constraint must fail the build, not the request.
    verifyNoEmptySecurityAnnotation(typeElement);
  }

  @Override
  protected CodeBlock defineMethodImplementation(ExecutableElement methodElement,
                                                 String methodName,
                                                 TypeElement typeElementTargetClass) {
    CodeBlock.Builder body = CodeBlock.builder();

    // R031: reject a method that carries more than one security annotation
    // before lowering it, so a dropped constraint cannot go unenforced.
    verifyAtMostOneSecurityAnnotation(methodElement);
    // BL02 (V00.81): an empty constraint must fail the build, not the request.
    verifyNoEmptySecurityAnnotation(methodElement);

    boolean guarded = emitGuard(body, methodElement, typeElementTargetClass);
    if (guarded && currentSourceFqn != null) {
      List<String> methods = indexBySource.get(currentSourceFqn);
      if (methods != null && !methods.contains(methodName)) {
        methods.add(methodName);
      }
    }

    String paramList = methodElement.getParameters().stream()
        .map(p -> p.getSimpleName().toString())
        .collect(Collectors.joining(", "));

    TypeMirror returnType = methodElement.getReturnType();
    if (returnType.getKind() == TypeKind.VOID) {
      body.addStatement("super.$L($L)", methodName, paramList);
    } else {
      body.addStatement("return super.$L($L)", methodName, paramList);
    }

    return body.build();
  }

  /**
   * JS-SEC-156 (CWE-862): validates, before the base processor decides whether
   * to generate the wrapper at all, that no restriction annotation sits on a
   * method the wrapper leaves alone. The base validation runs in any case, so
   * its own diagnostics are not lost.
   */
  @Override
  protected boolean validateTargetType(TypeElement typeElement) {
    boolean enforceable = verifyRestrictedMethodsAreWrapped(typeElement);
    return super.validateTargetType(typeElement) && enforceable;
  }

  /**
   * Emits a {@code processing/multiple-security-annotations} compile error when
   * {@code element} carries more than one restriction annotation. The
   * runtime scanner enforces "at most one annotation per element"; silently
   * picking the first match here would drop the other constraint without a
   * trace (R031), so the processor fails the compilation instead.
   *
   * <p>JS-SEC-156: the check counts every restriction annotation - the five
   * native ones, {@code @ProtectedBy} and consumer-defined ones - and only the
   * annotations directly present on the element. An annotation inherited from a
   * superclass is overridden by the subclass's own, exactly as the run-time
   * scanner resolves it, and is not a second annotation.
   */
  private void verifyAtMostOneSecurityAnnotation(Element element) {
    List<String> present = restrictionsOn(element).stream()
        .map(Binding::display)
        .toList();
    if (present.size() > 1) {
      messager.printMessage(Diagnostic.Kind.ERROR,
          "processing/multiple-security-annotations: " + element.getSimpleName()
              + " carries " + present.size() + " security annotations ("
              + String.join(", ", present)
              + "); at most one is allowed per element (matches the runtime "
              + "one-annotation-per-element scanner contract). Keep one, or split "
              + "the logic across separate methods.",
          element);
    }
  }

  /**
   * Emits a {@code processing/empty-security-annotation} compile error when a
   * security annotation on {@code element} carries an empty value array, a
   * blank entry, or a blank policy name (BL02, V00.81 / CWE-863). Before this
   * check the processor lowered e.g. {@code @RequiresPermission({})} into
   * {@code JCustosEnforcer.requireAllPermissions()} — a call that only
   * fails at request time with an {@code IllegalArgumentException}. The
   * runtime annotation scanner already denies empty constraints
   * (JS-SEC-010/011); the processor path now surfaces the misconfiguration
   * where it belongs: at compile time.
   */
  private void verifyNoEmptySecurityAnnotation(Element element) {
    RequiresPermission rp = element.getAnnotation(RequiresPermission.class);
    if (rp != null) {
      verifyValues(element, "@RequiresPermission", rp.value());
    }
    RequiresAllPermissions rap = element.getAnnotation(RequiresAllPermissions.class);
    if (rap != null) {
      verifyValues(element, "@RequiresAllPermissions", rap.value());
    }
    RequiresAnyPermission ranyp = element.getAnnotation(RequiresAnyPermission.class);
    if (ranyp != null) {
      verifyValues(element, "@RequiresAnyPermission", ranyp.value());
    }
    RequiresRole rr = element.getAnnotation(RequiresRole.class);
    if (rr != null) {
      verifyValues(element, "@RequiresRole", rr.value());
    }
    RequiresPolicy rpol = element.getAnnotation(RequiresPolicy.class);
    if (rpol != null && rpol.value().isBlank()) {
      emptyAnnotationError(element, "@RequiresPolicy", "a blank policy name");
    }
  }

  private void verifyValues(Element element, String annotationName, String[] values) {
    if (values.length == 0) {
      emptyAnnotationError(element, annotationName, "an empty value array");
      return;
    }
    for (String value : values) {
      if (value == null || value.isBlank()) {
        emptyAnnotationError(element, annotationName, "a blank entry");
        return;
      }
    }
  }

  private void emptyAnnotationError(Element element, String annotationName, String what) {
    messager.printMessage(Diagnostic.Kind.ERROR,
        "processing/empty-security-annotation: " + annotationName + " on "
            + element.getSimpleName() + " carries " + what
            + " — the generated guard would reject every call only at request "
            + "time. Name the required permission/role/policy, or remove the "
            + "annotation if the member is intentionally unguarded.",
        element);
  }

  /**
   * Appends the guard of one overridden method (JS-SEC-156, CWE-862). The
   * decision follows the run-time scanner behind
   * {@code JCustosEnforcer.enforce}: the method's own restriction first, then
   * the class.
   *
   * <ul>
   *   <li>A native restriction on the method, or - for a method declared in
   *       the {@code @Secured} class itself - a native restriction declared on
   *       that class, is lowered into the explicit enforcer API.</li>
   *   <li>Every other case gets the generic
   *       {@code JCustosEnforcer.enforce(Method, Class)} call: a restriction
   *       without native mapping, an inherited one, and no restriction at all.
   *       The last case is what makes deny-by-default (JS-SEC-081) apply to
   *       generated wrappers.</li>
   * </ul>
   *
   * @return {@code true} when a restriction known at compile time guards the
   * method; this feeds the wrapper index, which lists guarded methods only
   */
  private boolean emitGuard(CodeBlock.Builder body,
                            ExecutableElement method,
                            TypeElement securedType) {
    // Only evaluator bindings are restrictions - for the run-time scanner as well
    // (00.84.00). A @JCustosAnnotation binding to anything else, such as core's
    // @PropagateToken, is ignored on both paths and needs no special case here.
    List<Binding> restrictionsOnMethod = restrictionsOn(method);

    if (!restrictionsOnMethod.isEmpty()) {
      Optional<Class<? extends Annotation>> nativeType =
          nativeTypeOf(restrictionsOnMethod.getFirst());
      if (restrictionsOnMethod.size() == 1 && nativeType.isPresent()) {
        emitNativeCall(body, method, nativeType.get());
        return true;
      }
      emitGenericEnforce(body, method, securedType);
      return true;
    }

    TypeElement declaringType = (TypeElement) method.getEnclosingElement();
    if (declaringType.equals(securedType)) {
      // Only what the @Secured class declares itself is lowered natively. An
      // annotation inherited from a superclass, or contributed by an interface,
      // is resolved by the run-time scanner (most-derived wins) through the
      // generic call below, so both paths agree.
      List<Binding> restrictionsOnType = restrictionsOn(securedType);
      if (restrictionsOnType.size() == 1) {
        Optional<Class<? extends Annotation>> nativeType =
            nativeTypeOf(restrictionsOnType.getFirst());
        if (nativeType.isPresent()) {
          emitNativeCall(body, securedType, nativeType.get());
          return true;
        }
      }
    }

    // The scanner's order: the class that declares the method - unless the method
    // opts out with @PublicRoute - then the @Secured class, then a declaration the
    // method overrides or implements (JS-SEC-114). The generic call below enforces
    // all of it at run time; the flag only decides whether the wrapper index lists
    // the method as guarded (JS-SEC-159).
    boolean publicRoute = hasAnnotation(method, PublicRoute.class.getCanonicalName());
    boolean restricted =
        (!publicRoute && typeCarriesRestriction(declaringType))
            || typeCarriesRestriction(securedType)
            || (!publicRoute && overridesRestrictedDeclaration(method, securedType));

    emitGenericEnforce(body, method, securedType);
    return restricted;
  }

  /**
   * JS-SEC-156 (CWE-862): emits {@code JCustosEnforcer.enforce(Method, Class)}
   * for {@code method}. The {@link Method} is resolved once, in a static field
   * of the wrapper, against the {@code @Secured} class - the same element the
   * run-time path inspects - with the erased parameter types of the method.
   */
  private void emitGenericEnforce(CodeBlock.Builder body,
                                  ExecutableElement method,
                                  TypeElement securedType) {
    ClassName sourceClass = ClassName.get(securedType);
    if (guardMethodCount == 0) {
      typeSpecBuilderForTargetClass.addMethod(guardMethodResolver(securedType, sourceClass));
    }
    String field = GUARD_FIELD_PREFIX + guardMethodCount++;

    CodeBlock.Builder initializer = CodeBlock.builder()
        .add("$L($S", GUARD_RESOLVER, method.getSimpleName().toString());
    for (VariableElement parameter : method.getParameters()) {
      initializer.add(", $T.class", TypeName.get(typeUtils.erasure(parameter.asType())));
    }
    initializer.add(")");

    typeSpecBuilderForTargetClass.addField(FieldSpec
        .builder(Method.class, field, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer(initializer.build())
        .build());
    body.addStatement("$T.enforce($L, $T.class)", ENFORCER, field, sourceClass);
  }

  /**
   * The static helper the guard-method fields are initialised with. A method
   * that cannot be resolved - the wrapper is stale against its source class -
   * fails the initialisation of the wrapper class, so no call can slip through
   * unguarded.
   */
  private MethodSpec guardMethodResolver(TypeElement securedType, ClassName sourceClass) {
    String wrapperName = targetClassNameSimpleForGeneratedClass(securedType);
    return MethodSpec.methodBuilder(GUARD_RESOLVER)
        .addModifiers(Modifier.PRIVATE, Modifier.STATIC)
        .returns(Method.class)
        .addParameter(String.class, "name")
        .addParameter(ArrayTypeName.of(ParameterizedTypeName.get(
            ClassName.get(Class.class), WildcardTypeName.subtypeOf(Object.class))),
            "parameterTypes")
        .varargs()
        .addJavadoc("Resolves a guarded method of {@code $L} once, for\n"
            + "{@code JCustosEnforcer.enforce(Method, Class)} (JS-SEC-156).\n",
            securedType.getSimpleName().toString())
        .beginControlFlow("try")
        .addStatement("return $T.class.getMethod(name, parameterTypes)", sourceClass)
        .nextControlFlow("catch ($T e)", NoSuchMethodException.class)
        .addStatement("throw new $T($S + name + $S, e)",
            IllegalStateException.class,
            "jCustos: the generated wrapper " + wrapperName + " cannot resolve "
                + securedType.getQualifiedName() + "#",
            " - its security guard cannot be enforced. Recompile the wrapper "
                + "together with its source class.")
        .endControlFlow()
        .build();
  }

  /**
   * JS-SEC-156 (CWE-862): a restriction annotation on a method the wrapper does
   * not override was dropped without a diagnostic - the run-time path enforces
   * it, the generated wrapper did not even contain the method. Every such
   * method is a compile error now.
   *
   * <p>The walk covers the {@code @Secured} class, its superclasses and its
   * interfaces. A supertype method that a more derived type overrides is
   * skipped: annotations on methods are not inherited, the overriding method is
   * the one that counts.
   *
   * <p>Since 00.84.00 the check asks which restriction the run-time scanner
   * applies, not only which one the method carries: an unannotated method that
   * overrides a restricted declaration, and a public instance method under a
   * class-level restriction of the {@code @Secured} class, are restricted at run
   * time as well - and run for every caller when the wrapper leaves them out.
   * A public instance method left out without any restriction is a warning,
   * because deny-by-default cannot reach it. Every element of the walk is also
   * checked for a restriction composed more than one level deep.
   *
   * @return {@code true} when every restricted method is overridden by the wrapper
   */
  private boolean verifyRestrictedMethodsAreWrapped(TypeElement securedType) {
    Set<String> excludedNames = excludedMethodNames(securedType);
    List<ExecutableElement> moreDerived = new ArrayList<>();
    boolean enforceable = true;
    for (TypeElement type : typeClosure(securedType)) {
      enforceable &= verifyNoNestedComposition(type);
      for (ExecutableElement method : ElementFilter.methodsIn(type.getEnclosedElements())) {
        enforceable &= verifyNoNestedComposition(method);
        boolean overridden = moreDerived.stream()
            .anyMatch(derived -> elementUtils.overrides(derived, method, securedType));
        moreDerived.add(method);
        if (overridden) {
          continue;
        }
        Optional<String> reason = notWrappedBecause(method, excludedNames);
        if (reason.isEmpty()) {
          continue;
        }
        List<Binding> restrictions = restrictionsOn(method);
        if (!restrictions.isEmpty()) {
          enforceable = false;
          messager.printMessage(Diagnostic.Kind.ERROR,
              DIAG_UNENFORCEABLE + ": " + restrictions.getFirst().display() + " on "
                  + type.getSimpleName() + "#" + method.getSimpleName()
                  + " cannot be enforced by the generated wrapper of "
                  + securedType.getSimpleName() + " — the method " + reason.get()
                  + ", and the wrapper overrides public, non-final, non-static "
                  + "methods only, so the annotation would have no effect. Make the "
                  + "method public and overridable, or remove the annotation and "
                  + "guard the call explicitly through JCustosEnforcer.",
              method);
          continue;
        }
        enforceable &= verifyAppliedRestrictionIsWrapped(method, type, securedType,
            reason.get());
      }
    }
    return enforceable;
  }

  /**
   * XR06 (00.84.00, CWE-862): {@code method} carries no restriction of its own and
   * the wrapper does not override it. Reports the restriction the run-time scanner
   * would apply to it anyway - in the scanner's order: {@link PublicRoute @PublicRoute}
   * on the method opts out, then the class-level restriction of the {@code @Secured}
   * class, then a restricted declaration the method overrides - as an error; a
   * public instance method without any as a deny-by-default warning.
   *
   * <p>Static and private methods are neither reached through the wrapper nor
   * override anything, and the wrapper never overrides an {@link Object} method;
   * they are left alone. A protected or package-private method is not part of the
   * class's public surface, so a class-level restriction is not reported for it -
   * but overriding a restricted declaration is.
   *
   * @return {@code false} when a restriction applies that the wrapper cannot enforce
   */
  private boolean verifyAppliedRestrictionIsWrapped(ExecutableElement method,
                                                    TypeElement type,
                                                    TypeElement securedType,
                                                    String reason) {
    Set<Modifier> modifiers = method.getModifiers();
    if (modifiers.contains(Modifier.STATIC) || modifiers.contains(Modifier.PRIVATE)
        || isObjectMethod(method)
        || hasAnnotation(method, PublicRoute.class.getCanonicalName())) {
      return true;
    }
    boolean publicMethod = modifiers.contains(Modifier.PUBLIC);
    String where = type.getSimpleName() + "#" + method.getSimpleName();
    Optional<String> applied = Optional.empty();
    if (publicMethod) {
      applied = classLevelRestriction(securedType).map(origin ->
          "the class-level restriction " + origin + " applies to " + where);
    }
    if (applied.isEmpty()) {
      applied = overriddenRestrictedDeclaration(method, securedType).map(declaration ->
          where + " overrides or implements "
              + declaration.getEnclosingElement().getSimpleName() + "#"
              + declaration.getSimpleName() + ", whose "
              + restrictionsOn(declaration).getFirst().display() + " applies to it");
    }
    if (applied.isPresent()) {
      messager.printMessage(Diagnostic.Kind.ERROR,
          DIAG_UNENFORCEABLE + ": " + applied.get() + " at run time - SecuredProxy and "
              + "JCustosEnforcer.enforce deny unauthorised calls - but the method "
              + reason + ", so the generated wrapper of " + securedType.getSimpleName()
              + " does not override it and runs it for every caller. Make the method "
              + "public and overridable, put @PublicRoute on it if it is meant to be "
              + "open, or guard the call explicitly through JCustosEnforcer.",
          method);
      return false;
    }
    if (publicMethod && securedType.getAnnotation(PublicRoute.class) == null) {
      messager.printMessage(Diagnostic.Kind.WARNING,
          DIAG_NO_DENY_BY_DEFAULT + ": " + where + " is not overridden by the generated "
              + "wrapper of " + securedType.getSimpleName() + " - the method " + reason
              + " - so deny-by-default does not cover it. Give it a restriction or "
              + "@PublicRoute, or make it public and overridable.",
          method);
    }
    return true;
  }

  /**
   * The class-level restriction the run-time scanner finds for the
   * {@code @Secured} class - the class itself, its superclasses, then its
   * interfaces - rendered for a diagnostic.
   */
  private Optional<String> classLevelRestriction(TypeElement securedType) {
    for (TypeElement candidate : typeClosure(securedType)) {
      List<Binding> restrictions = restrictionsOn(candidate);
      if (!restrictions.isEmpty()) {
        return Optional.of(restrictions.getFirst().display() + " of "
            + candidate.getSimpleName());
      }
    }
    return Optional.empty();
  }

  /**
   * XR08 (00.84.00, CWE-862): the run-time scanner resolves a composed restriction
   * one level deep and throws for anything deeper, because treating the element as
   * unrestricted would open it. The processor reports such an element at compile
   * time: an annotation whose type carries an annotation that composes a
   * restriction in turn ({@code @AdminOnly @interface SuperAdmin}).
   *
   * @return {@code true} when {@code element} carries no such annotation
   */
  private boolean verifyNoNestedComposition(Element element) {
    boolean resolvable = true;
    for (AnnotationMirror mirror : element.getAnnotationMirrors()) {
      if (!(mirror.getAnnotationType().asElement() instanceof TypeElement annotationType)) {
        continue;
      }
      for (AnnotationMirror meta : annotationType.getAnnotationMirrors()) {
        if (meta.getAnnotationType().asElement() instanceof TypeElement metaType
            && !isRestrictionType(metaType)
            && composesRestriction(metaType, new LinkedHashSet<>())) {
          resolvable = false;
          messager.printMessage(Diagnostic.Kind.ERROR,
              DIAG_NESTED_COMPOSITION + ": @" + annotationType.getSimpleName() + " on "
                  + element.getSimpleName() + " carries @" + metaType.getSimpleName()
                  + ", which composes a restriction itself. A composed restriction is "
                  + "resolved one level deep only, and JCustosEnforcer.enforce refuses "
                  + "a deeper one at run time. Put the restriction on @"
                  + annotationType.getSimpleName() + " directly.",
              element);
        }
      }
    }
    return resolvable;
  }

  /** Whether {@code @JCustosAnnotation} on {@code annotationType} binds an evaluator. */
  private boolean isRestrictionType(TypeElement annotationType) {
    return jCustosAnnotationOf(annotationType).map(this::bindsEvaluator).orElse(false);
  }

  /**
   * Whether an annotation of {@code annotationType} brings a restriction with it at
   * any depth. {@code visited} breaks the cycles annotation types may form.
   */
  private boolean composesRestriction(TypeElement annotationType, Set<TypeElement> visited) {
    if (!visited.add(annotationType)) {
      return false;
    }
    for (AnnotationMirror meta : annotationType.getAnnotationMirrors()) {
      if (meta.getAnnotationType().asElement() instanceof TypeElement metaType
          && (isRestrictionType(metaType) || composesRestriction(metaType, visited))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Why the wrapper does not override {@code method}; empty when it does. Mirrors
   * the method filter of the proxybuilder base processor.
   */
  private Optional<String> notWrappedBecause(ExecutableElement method,
                                             Set<String> excludedNames) {
    Set<Modifier> modifiers = method.getModifiers();
    if (modifiers.contains(Modifier.PRIVATE)) {
      return Optional.of("is private");
    }
    if (modifiers.contains(Modifier.STATIC)) {
      return Optional.of("is static");
    }
    if (modifiers.contains(Modifier.FINAL)) {
      return Optional.of("is final");
    }
    if (!modifiers.contains(Modifier.PUBLIC)) {
      return Optional.of(modifiers.contains(Modifier.PROTECTED)
          ? "is protected" : "is package-private");
    }
    if (isObjectMethod(method)) {
      return Optional.of("is an Object method (equals, hashCode, toString, finalize), "
          + "which the wrapper never overrides");
    }
    if (method.getAnnotation(SkipProxy.class) != null) {
      return Optional.of("is excluded from the wrapper by @SkipProxy");
    }
    if (excludedNames.contains(method.getSimpleName().toString())) {
      return Optional.of("is excluded from the wrapper by "
          + "@ProxyBuilderOptions(excludeMethodNames)");
    }
    return Optional.empty();
  }

  private static Set<String> excludedMethodNames(TypeElement securedType) {
    ProxyBuilderOptions options = securedType.getAnnotation(ProxyBuilderOptions.class);
    return options == null ? Set.of() : Set.of(options.excludeMethodNames());
  }

  // ── restriction model (JS-SEC-156) ───────────────────────────────

  /**
   * A restriction an element carries, found the way the run-time scanner finds
   * it: an annotation directly present on the element whose annotation type is
   * meta-annotated with {@link JCustosAnnotation}, or - one level deep - such an
   * annotation on the annotation type of an annotation the element carries (a
   * composed annotation, JS-SEC-154).
   *
   * @param annotationType the annotation type written on the element
   * @param evaluatorBound whether {@code @JCustosAnnotation} binds it to an
   *                       {@link AccessEvaluator} or {@link AuthorizationEvaluator},
   *                       which is what makes it a restriction the enforcer can
   *                       evaluate
   * @param composedOf     for a composed annotation the restriction annotation on
   *                       its type, otherwise {@code null}; a composed restriction
   *                       is never lowered natively
   */
  private record Binding(TypeElement annotationType, boolean evaluatorBound, TypeElement composedOf) {

    String display() {
      return composedOf == null
          ? "@" + annotationType.getSimpleName()
          : "@" + annotationType.getSimpleName() + " (composed of @" + composedOf.getSimpleName() + ")";
    }
  }

  private List<Binding> declaredBindings(Element element) {
    List<Binding> bindings = new ArrayList<>();
    for (AnnotationMirror mirror : element.getAnnotationMirrors()) {
      if (!(mirror.getAnnotationType().asElement() instanceof TypeElement annotationType)) {
        continue;
      }
      jCustosAnnotationOf(annotationType).ifPresent(binding ->
          bindings.add(new Binding(annotationType, bindsEvaluator(binding), null)));
      // JS-SEC-154 (CWE-862): the run-time scanner resolves a composed annotation such as
      // `@RequiresRole("ADMIN") @interface AdminOnly` one level deep. The processor did not:
      // on a class with a native class-level restriction it lowered the class restriction for
      // such a method, and the wrapper granted what SecuredProxy denied.
      for (AnnotationMirror meta : annotationType.getAnnotationMirrors()) {
        if (meta.getAnnotationType().asElement() instanceof TypeElement metaType) {
          jCustosAnnotationOf(metaType).ifPresent(binding ->
              bindings.add(new Binding(annotationType, bindsEvaluator(binding), metaType)));
        }
      }
    }
    return bindings;
  }

  /** The {@code @JCustosAnnotation} on {@code annotationType}, if it carries one. */
  private static Optional<AnnotationMirror> jCustosAnnotationOf(TypeElement annotationType) {
    for (AnnotationMirror meta : annotationType.getAnnotationMirrors()) {
      if (meta.getAnnotationType().asElement() instanceof TypeElement metaType
          && metaType.getQualifiedName()
          .contentEquals(JCustosAnnotation.class.getCanonicalName())) {
        return Optional.of(meta);
      }
    }
    return Optional.empty();
  }

  /** The restriction annotations directly present on {@code element}. */
  private List<Binding> restrictionsOn(Element element) {
    return declaredBindings(element).stream()
        .filter(Binding::evaluatorBound)
        .toList();
  }

  private boolean bindsEvaluator(AnnotationMirror jCustosAnnotation) {
    for (Map.Entry<? extends ExecutableElement, ? extends AnnotationValue> entry
        : jCustosAnnotation.getElementValues().entrySet()) {
      if (entry.getKey().getSimpleName().contentEquals("value")
          && entry.getValue().getValue() instanceof TypeMirror bound) {
        TypeMirror erased = typeUtils.erasure(bound);
        return Stream.of(AccessEvaluator.class, AuthorizationEvaluator.class)
            .map(evaluator -> elementUtils.getTypeElement(evaluator.getCanonicalName()))
            .anyMatch(evaluator -> evaluator != null
                && typeUtils.isAssignable(erased, typeUtils.erasure(evaluator.asType())));
      }
    }
    // Not resolvable at this point: treat it as a restriction, the guarded side.
    return true;
  }

  private static Optional<Class<? extends Annotation>> nativeTypeOf(Binding binding) {
    if (binding.composedOf() != null) {
      // The values sit on the composed annotation's type, not on the element.
      return Optional.empty();
    }
    return SECURITY_ANNOTATIONS.stream()
        .filter(candidate -> binding.annotationType().getQualifiedName()
            .contentEquals(candidate.getCanonicalName()))
        .findFirst();
  }

  /**
   * Whether {@code type}, one of its superclasses or one of its interfaces
   * declares a restriction - the class-level walk of the run-time scanner.
   */
  private boolean typeCarriesRestriction(TypeElement type) {
    return typeClosure(type).stream()
        .anyMatch(candidate -> !restrictionsOn(candidate).isEmpty());
  }

  /**
   * JS-SEC-159 (CWE-862): whether {@code method}, as a member of the {@code @Secured}
   * class, overrides or implements a supertype declaration that carries a
   * restriction. Annotations on methods are not inherited in Java; the run-time
   * scanner looks for such a declaration after the class-level restriction, and the
   * generic guard the wrapper emits applies it.
   */
  private boolean overridesRestrictedDeclaration(ExecutableElement method, TypeElement securedType) {
    return overriddenRestrictedDeclaration(method, securedType).isPresent();
  }

  /** The first restricted supertype declaration {@code method} overrides or implements. */
  private Optional<ExecutableElement> overriddenRestrictedDeclaration(ExecutableElement method,
                                                                      TypeElement securedType) {
    Element declaringType = method.getEnclosingElement();
    for (TypeElement type : typeClosure(securedType)) {
      if (type.equals(declaringType)) {
        continue;
      }
      for (ExecutableElement candidate : ElementFilter.methodsIn(type.getEnclosedElements())) {
        if (!restrictionsOn(candidate).isEmpty()
            && elementUtils.overrides(method, candidate, securedType)) {
          return Optional.of(candidate);
        }
      }
    }
    return Optional.empty();
  }

  /** {@code type}, then its superclasses, then every interface; without {@link Object}. */
  private Set<TypeElement> typeClosure(TypeElement type) {
    Set<TypeElement> closure = new LinkedHashSet<>();
    collectTypeClosure(type, closure);
    return closure;
  }

  private void collectTypeClosure(TypeElement type, Set<TypeElement> closure) {
    if (type == null
        || type.getQualifiedName().contentEquals(Object.class.getCanonicalName())
        || !closure.add(type)) {
      return;
    }
    if (typeUtils.asElement(type.getSuperclass()) instanceof TypeElement superclass) {
      collectTypeClosure(superclass, closure);
    }
    for (TypeMirror implemented : type.getInterfaces()) {
      if (typeUtils.asElement(implemented) instanceof TypeElement implementedType) {
        collectTypeClosure(implementedType, closure);
      }
    }
  }

  /**
   * Appends the explicit enforcer call for the native annotation
   * {@code nativeType} on {@code element}.
   */
  private void emitNativeCall(CodeBlock.Builder body,
                              Element element,
                              Class<? extends Annotation> nativeType) {
    Annotation annotation = element.getAnnotation(nativeType);
    switch (annotation) {
      case RequiresPermission rp -> {
        if (rp.value().length == 1) {
          body.addStatement("$T.requirePermission($S)", ENFORCER, rp.value()[0]);
        } else {
          emitVarargsCall(body, "requireAllPermissions", rp.value());
        }
      }
      case RequiresAllPermissions rap ->
          emitVarargsCall(body, "requireAllPermissions", rap.value());
      case RequiresAnyPermission ranyp ->
          emitVarargsCall(body, "requireAnyPermission", ranyp.value());
      case RequiresRole rr -> {
        if (rr.value().length == 1) {
          body.addStatement("$T.requireRole($S)", ENFORCER, rr.value()[0]);
        } else {
          emitVarargsCall(body, "requireAnyRole", rr.value());
        }
      }
      case RequiresPolicy rpol ->
          body.addStatement("$T.requirePolicy($S)", ENFORCER, rpol.value());
      default -> throw new IllegalStateException(
          "no native lowering for @" + nativeType.getSimpleName());
    }
  }

  private static void emitVarargsCall(CodeBlock.Builder body,
                                      String enforcerMethod,
                                      String[] values) {
    StringBuilder format = new StringBuilder("$T.").append(enforcerMethod).append("(");
    Object[] args = new Object[values.length + 1];
    args[0] = ENFORCER;
    for (int i = 0; i < values.length; i++) {
      if (i > 0) {
        format.append(", ");
      }
      format.append("$S");
      args[i + 1] = values[i];
    }
    format.append(")");
    body.addStatement(format.toString(), args);
  }

  /**
   * Writes the merged wrapper index in {@code processingOver()}. Reads
   * the pre-existing file once, merges the entries collected in this
   * compilation (replacing prior entries for the same source FQN), and
   * writes a deterministic, alphabetically sorted file. Failures are
   * {@link Diagnostic.Kind#WARNING} — wrapper generation success is
   * never affected by index-write problems.
   *
   * <p>Implementation notes (matching Konzept §11.3):
   * <ul>
   *   <li>{@link javax.annotation.processing.Filer#getResource} may throw
   *       {@link IOException} or {@link UnsupportedOperationException}
   *       in some in-memory file managers; both are treated as
   *       "no prior file present".</li>
   *   <li>{@link javax.annotation.processing.Filer#createResource} may
   *       throw {@link FilerException} on re-write; the writer runs in
   *       {@code processingOver()} so it is invoked exactly once per
   *       compilation.</li>
   * </ul>
   */
  private void writeIndex() {
    Map<String, List<String>> merged = readExistingIndex();
    indexBySource.forEach(merged::put);

    if (merged.isEmpty()) {
      return;
    }

    try {
      FileObject out = filer.createResource(
          StandardLocation.CLASS_OUTPUT, "", INDEX_RESOURCE_PATH);
      try (Writer w = out.openWriter()) {
        w.write(INDEX_MARKER_COMMENT);
        w.write("\n");
        for (Map.Entry<String, List<String>> e : merged.entrySet()) {
          String sourceFqn = e.getKey();
          String generatedFqn = sourceFqn + "Secured";
          // de-dup methods while preserving insertion order
          String methods = new LinkedHashSet<>(e.getValue()).stream()
              .collect(Collectors.joining(INDEX_METHOD_SEPARATOR));
          w.write(sourceFqn);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(generatedFqn);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(INDEX_PROCESSOR_ID);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(INDEX_PROXYBUILDER_VERSION);
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(methods);
          // V00.74 sixth field — wrapper kind.
          w.write(INDEX_FIELD_SEPARATOR);
          w.write(INDEX_KIND_SECURED);
          w.write("\n");
        }
      }
    } catch (FilerException fe) {
      messager.printMessage(Diagnostic.Kind.WARNING,
          "processor/index-write-failed: " + fe.getMessage());
    } catch (IOException io) {
      messager.printMessage(Diagnostic.Kind.WARNING,
          "processor/index-write-failed: " + io.getMessage());
    }
  }

  /**
   * The version of the proxybuilder base processor on the processor path, from the
   * Maven metadata of its jar; {@link #UNKNOWN_PROXYBUILDER_VERSION} if that cannot
   * be read or would not fit into an index field.
   */
  static String proxyBuilderVersion() {
    ClassLoader loader = BasicStaticProxyAnnotationProcessor.class.getClassLoader();
    try (InputStream in = loader == null
        ? ClassLoader.getSystemResourceAsStream(PROXYBUILDER_POM_PROPERTIES)
        : loader.getResourceAsStream(PROXYBUILDER_POM_PROPERTIES)) {
      if (in == null) {
        return UNKNOWN_PROXYBUILDER_VERSION;
      }
      Properties properties = new Properties();
      properties.load(in);
      String version = properties.getProperty(PROXYBUILDER_VERSION_KEY, "").strip();
      boolean fitsTheIndex = !version.isEmpty()
          && version.chars().noneMatch(c -> c == ':' || c == ',' || Character.isWhitespace(c));
      return fitsTheIndex ? version : UNKNOWN_PROXYBUILDER_VERSION;
    } catch (IOException | RuntimeException unreadable) {
      return UNKNOWN_PROXYBUILDER_VERSION;
    }
  }

  private Map<String, List<String>> readExistingIndex() {
    Map<String, List<String>> result = new TreeMap<>();
    try {
      FileObject existing = filer.getResource(
          StandardLocation.CLASS_OUTPUT, "", INDEX_RESOURCE_PATH);
      try (BufferedReader r = new BufferedReader(existing.openReader(true))) {
        String line;
        while ((line = r.readLine()) != null) {
          if (line.isBlank() || line.startsWith("#")) {
            continue;
          }
          String[] parts = line.split(INDEX_FIELD_SEPARATOR, 6);
          if (parts.length < 5) {
            continue;
          }
          List<String> methods = parts[4].isBlank()
              ? new ArrayList<>()
              : new ArrayList<>(Arrays.asList(parts[4].split(INDEX_METHOD_SEPARATOR)));
          methods.replaceAll(String::trim);
          result.put(parts[0].trim(), methods);
        }
      }
    } catch (IOException | RuntimeException ignored) {
      // No prior file (or unreadable resource in in-memory file manager)
      // → start with an empty map. RuntimeException covers
      // UnsupportedOperationException from some Filer implementations.
    }
    return result;
  }
}
