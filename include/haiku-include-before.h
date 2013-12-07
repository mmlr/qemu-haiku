/*
 * Copyright 2013 Michael Lotz <mmlr@mlotz.ch>
 * All rights reserved. Distributed under the terms of the MIT license.
 */
#ifndef HAIKU_INCLUDE_BEFORE_H
#define HAIKU_INCLUDE_BEFORE_H

/*
  This header is included before any Haiku headers. It ensures that no name
  clashes occur with internal names.
 */

#define load_image haiku_load_image
#undef atomic_set
#undef atomic_add
#undef atomic_and
#undef atomic_or

#endif /* HAIKU_INCLUDE_BEFORE_H */
