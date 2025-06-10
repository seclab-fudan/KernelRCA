<script setup>
import { Handle, Position, useVueFlow } from "@vue-flow/core";
import { ref, computed } from 'vue';
import eventBus from '@/utils/eventBus';
const props = defineProps({
  id: {
    type: String,
    required: true,
  },
  insName: {
    type: String,
    required: true,
  },
  insDesc: {
    type: String,
  }
})
const isHighlighted = ref(false);
const { updateNodeInternals } = useVueFlow();

const onNodeClick = () => {
  eventBus.emit('node-clicked', { type: 'insItem', id: props.id });
};

eventBus.on('highlight-nodes', (highlightedNodes) => {
  isHighlighted.value = highlightedNodes.insItemId === Number(props.id);
});

const insbox = computed(() => {
  return isHighlighted.value ? 'highlightedIns nodrag' : 'normalIns nodrag';
});

</script>

<template>
  <div :class="insbox" @click="onNodeClick">
    <div class="ins-content">
      <p class="ins-name">{{ insName }}</p>
      <p class="ins-desc" v-if="insDesc">{{ insDesc }}</p>
    </div>
    <div class="ins-anchor">
      <Handle id="bottomSource" :position="Position.Bottom" type="source" style="opacity: 0;top: 0" />
      <Handle id="rightSource" :position="Position.Right" type="source" style="opacity: 0;margin-top: 5px" />
      <Handle id="leftSource" :position="Position.Left" type="source" style="opacity: 0;margin-top: 5px" />

      <Handle id="topTarget" :position="Position.Top" type="target" style="opacity: 0;" />
      <Handle id="rightTarget" :position="Position.Right" type="target" style="opacity: 0;padding-left: 2px" />
      <Handle id="leftTarget" :position="Position.Left" type="target" style="opacity: 0;padding-right: 2px" />
    </div>
  </div>
</template>


<style>
.ins-anchor {
  width: 0;
  //position: relative;
}

.highlightedIns {
  position: relative;
  display: flex;
  flex-direction: column;
  border: 1px solid black;
  border-radius: 8px;
  width: 17vw;
  padding: 2px;
  cursor: pointer;
  background-color: var(--active--color);
}

.normalIns {
  position: relative;
  display: flex;
  flex-direction: column;
  border: 1px solid black;
  border-radius: 8px;
  width: 17vw;
  padding: 2px;
  cursor: pointer;
  background-color: white;
}

.highlightedIns:hover {
  background-color: var(--cover--bggcolor);
}

.normalIns:hover {
  background-color: var(--cover--bggcolor);
}

.ins-content {
  display: flex;
  flex-direction: column;
}

.ins-name {
  font-size: 14px;
  font-weight: bold;
  margin: 0;
  padding: 0 0 1px 0;
  align-items: center;
  text-align: center;
  font-family: 'Consolas', monospace;
}

.ins-desc {
  font-size: 12px;
  color: #ffffff;
  background-color: #2d902d;
  border-radius: 4px;
  padding: 2px;
  margin: 0;
  word-wrap: break-word;
  white-space: pre-line;
  font-family: Arial, sans-serif;
}
</style>