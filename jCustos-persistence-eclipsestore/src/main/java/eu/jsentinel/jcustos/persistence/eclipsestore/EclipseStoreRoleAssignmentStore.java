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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentKey;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentStore;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.LinkedHashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link RoleAssignmentStore}; one entry per subject
 * that holds a role, not bounded — assignments are written by an
 * administrative action.
 */
final class EclipseStoreRoleAssignmentStore implements RoleAssignmentStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreRoleAssignmentStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Set<RoleName> findRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    return storage.read(() -> {
      Set<RoleName> roles = storage.tables().roleAssignments.get(key);
      return roles == null ? Set.of() : Set.copyOf(roles);
    });
  }

  @Override
  public void setRoles(RoleAssignmentKey key, Set<RoleName> roles) {
    requireNonNull(key, "key must not be null");
    storage.update(() -> {
      if (roles == null || roles.isEmpty()) {
        storage.tables().roleAssignments.remove(key);
      } else {
        storage.tables().roleAssignments.put(key, new LinkedHashSet<>(roles));
      }
    });
  }

  @Override
  public boolean assignRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    return storage.write(() -> {
      LinkedHashSet<RoleName> set = storage.tables().roleAssignments.get(key);
      if (set == null) {
        set = new LinkedHashSet<>();
        storage.tables().roleAssignments.put(key, set);
      }
      boolean added = set.add(role);
      if (added) {
        // the set is changed in place: it has to be stored itself, storing what
        // refers to it would not write it again (R002)
        storage.markChanged(set);
      }
      return added;
    });
  }

  @Override
  public boolean revokeRole(RoleAssignmentKey key, RoleName role) {
    requireNonNull(key, "key must not be null");
    requireNonNull(role, "role must not be null");
    return storage.write(() -> {
      LinkedHashSet<RoleName> set = storage.tables().roleAssignments.get(key);
      if (set == null) {
        return false;
      }
      boolean removed = set.remove(role);
      if (removed) {
        if (set.isEmpty()) {
          storage.tables().roleAssignments.remove(key);
        } else {
          storage.markChanged(set); // changed in place (R002)
        }
      }
      return removed;
    });
  }

  @Override
  public void clearRoles(RoleAssignmentKey key) {
    requireNonNull(key, "key must not be null");
    storage.update(() -> storage.tables().roleAssignments.remove(key));
  }
}
