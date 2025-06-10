<script setup>
import { Position, Handle } from '@vue-flow/core'
import { ref, computed } from 'vue';
import eventBus from '@/utils/eventBus';

// props were passed from the slot using `v-bind="customNodeProps"`
const props = defineProps({
  id: {
    type: String,
    required: true,
  },
  callName: {
    type: String,
    required: true,
  }
})

const isHighlighted = ref(false);
const onNodeClick = () => {
  // 通知父组件哪个节点被点击了
  eventBus.emit('node-clicked', { type: 'callNode', id: props.id });
};

// 监听来自父组件的高亮事件
eventBus.on('highlight-nodes', (highlightedNodes) => {
  // 更新高亮状态，判断是否需要高亮
  isHighlighted.value = highlightedNodes.callNodeId === Number(props.id);
});

const text = computed(() => {
  return isHighlighted.value ? 'highlighted' : 'normal';
});
</script>

<template>
    <div class="box nodrag">
      <div :class="text" @click="onNodeClick">{{ props.callName }}</div>
        <div class="anchor">
            <Handle type="target" :position="Position.Left" style="opacity: 0" />
            <Handle type="source" :position="Position.Bottom" style="opacity: 0" />
        </div>
    </div>
</template>

<style>
.box{
  position: relative;
  display: flex;
  width: 100%;
  height: 14px;
  cursor: pointer; /* 鼠标悬停时变为手型 */
}
.highlighted {
  background-color: var(--active--color);
  position: absolute;
  left: 0;
  flex: 1;
  padding: 0;
  text-align: left;
  font-size: 14px;
  transition: background-color 0.1s; /* 添加过渡效果，改变背景时更平滑 */
}
.highlighted:hover{
  background-color: var(--cover--bggcolor);
}
.normal{
  position: absolute;
  left: 0;
  flex: 1;
  padding: 0;
  text-align: left;
  font-size: 14px;
  transition: background-color 0.1s; /* 添加过渡效果，改变背景时更平滑 */
}
.normal:hover{
  background-color: var(--cover--bggcolor);
}

.anchor {
    width: 14px;
    padding: 0;
}


</style>
