# encoding: UTF-8
#
# Shared scoping helper, mixed into the control-eval context so every control
# can call `scoped_or_na` directly.
#
# ---- The problem it exists to remove -----------------------------------------
#
# Many controls here loop over a collection and describe each member. The account can simply
# hold none of that resource — no EC2 instances, no
# EBS volumes, no EFS file systems, no IAM server certificates — and the loop then never executes. Without
# care the control registers no `describe` blocks and emits ZERO results:
# neither passed nor Not Applicable, but ABSENT. A control that asserts nothing
# while reporting not-red is the failure this profile exists to catch, and it
# also breaks the evidence pipeline, because the HDF v3 schema requires at least
# one result per requirement and `hdf convert` refuses the whole document
# without it.
#
# Expressing that inline cost every control the same eight lines — hoist the
# collection, fold emptiness into `applicable`, set impact, write only_if. Said
# once here instead, each control keeps only what is actually specific to it:
# which collection, why it might be out of scope, and what to assert.
#
# ---- Why a module and not a constant ----------------------------------------
#
# InSpec evaluates each control FILE in its own anonymous context, so a constant
# defined in one is invisible in another. A module mixed into ::Inspec::Rule is
# reachable from every control body, and `self` inside a control IS the rule —
# which is what lets this call `impact` and `only_if` on the caller's behalf.
#
# The leading `::` on ::Inspec::Rule is load-bearing: the bare form raises an
# uninitialized-constant NameError at exec time under InSpec 7, and `check`
# does not catch it because check only loads.
module ScopedCollection
  # Returns the collection, and declares the control Not Applicable when it is
  # empty or otherwise out of scope.
  #
  #   impact 0.5
  #   scoped_items = scoped_or_na(aws_ec2_instances.instance_ids,
  #                               in_scope: applicable_partition,
  #                               reason:   "Control out of scope (...) or no EC2 instances")
  #   scoped_items.each { |id| describe ... }
  #
  # Callers set their own `impact` first; this only ever lowers it to 0.0, so a
  # control keeps its declared severity when it applies.
  def scoped_or_na(collection, in_scope:, reason:)
    items      = Array(collection)
    applicable = in_scope && !items.empty?
    impact 0.0 unless applicable
    only_if(reason) { applicable }
    items
  end
end

::Inspec::Rule.include(ScopedCollection)
